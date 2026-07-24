/* vi: set sw=4 ts=4: */
/*
 * Utility routines.
 *
 * Copyright 1998 by Albert Cahalan; all rights reserved.
 * Copyright (C) 2002 by Vladimir Oleynik <dzo@simtreas.ru>
 * SELinux support: (c) 2007 by Yuichi Nakamura <ynakam@hitachisoft.jp>
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */
#include "libbb.h"

#if defined(__CYGWIN__)
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
# include <winternl.h>

# define BB_STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xc0000004L)

static procps_status_t* FAST_FUNC alloc_procps_scan(void);

typedef struct {
	USHORT length;
	USHORT maximum_length;
	PWSTR buffer;
} bb_win_unicode_string;

static char *win_wide_to_utf8(const WCHAR *src, unsigned wchar_count)
{
	char *dst;
	int len;

	if (!src || wchar_count == 0)
		return NULL;
	len = WideCharToMultiByte(CP_UTF8, 0, src, wchar_count,
			NULL, 0, NULL, NULL);
	if (len <= 0)
		return NULL;
	dst = xmalloc(len + 1);
	WideCharToMultiByte(CP_UTF8, 0, src, wchar_count,
			dst, len, NULL, NULL);
	dst[len] = '\0';
	return dst;
}

static void *win_process_snapshot(void)
{
	ULONG size = 512 * 1024;
	void *buf = NULL;

	for (;;) {
		ULONG needed = 0;
		NTSTATUS status;

		buf = xrealloc(buf, size);
		status = NtQuerySystemInformation(SystemProcessInformation,
				buf, size, &needed);
		if (status == BB_STATUS_INFO_LENGTH_MISMATCH) {
			size = needed > size ? needed + 64 * 1024 : size * 2;
			continue;
		}
		if (status < 0) {
			free(buf);
			errno = EIO;
			return NULL;
		}
		return buf;
	}
}

static char *win_process_image_path(unsigned pid)
{
	WCHAR path[1024];
	DWORD length = ARRAY_SIZE(path);
	HANDLE process;
	char *result = NULL;

	process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (!process)
		return NULL;
	if (QueryFullProcessImageNameW(process, 0, path, &length))
		result = win_wide_to_utf8(path, length);
	CloseHandle(process);
	return result;
}

static void win_process_user(unsigned pid, char *dst, unsigned dst_size)
{
	HANDLE process;
	HANDLE token;
	DWORD size = 0;
	void *token_buf = NULL;
	WCHAR name[256];
	WCHAR domain[256];
	DWORD name_size = ARRAY_SIZE(name);
	DWORD domain_size = ARRAY_SIZE(domain);
	SID_NAME_USE sid_type;
	char *utf8_name = NULL;

	process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (!process)
		return;
	if (!OpenProcessToken(process, TOKEN_QUERY, &token))
		goto close_process;
	GetTokenInformation(token, TokenUser, NULL, 0, &size);
	if (!size)
		goto close_token;
	token_buf = xmalloc(size);
	if (!GetTokenInformation(token, TokenUser, token_buf, size, &size))
		goto close_token;
	if (!LookupAccountSidW(NULL, ((TOKEN_USER *)token_buf)->User.Sid,
			name, &name_size, domain, &domain_size, &sid_type))
		goto close_token;
	utf8_name = win_wide_to_utf8(name, name_size);
	if (utf8_name)
		safe_strncpy(dst, utf8_name, dst_size);

 close_token:
	free(utf8_name);
	free(token_buf);
	CloseHandle(token);
 close_process:
	CloseHandle(process);
}

static char *win_process_command_line(unsigned pid)
{
	PROCESS_BASIC_INFORMATION info;
	ULONG returned;
	HANDLE process;
	PVOID params;
	bb_win_unicode_string command_line;
	WCHAR *wide = NULL;
	SIZE_T bytes_read;
	char *result = NULL;
	SIZE_T params_offset;
	SIZE_T command_line_offset;

# if defined(__x86_64__)
	params_offset = 0x20;
	command_line_offset = 0x70;
# else
	params_offset = 0x10;
	command_line_offset = 0x40;
# endif

	process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			FALSE, pid);
	if (!process)
		return NULL;
	if (NtQueryInformationProcess(process, ProcessBasicInformation,
			&info, sizeof(info), &returned) < 0)
		goto done;
	if (!ReadProcessMemory(process,
			(char *)info.PebBaseAddress + params_offset,
			&params, sizeof(params), &bytes_read)
	 || bytes_read != sizeof(params)
	 || !params)
		goto done;
	if (!ReadProcessMemory(process,
			(char *)params + command_line_offset,
			&command_line, sizeof(command_line), &bytes_read)
	 || bytes_read != sizeof(command_line)
	 || !command_line.buffer
	 || command_line.length == 0
	 || command_line.length > 64 * 1024)
		goto done;
	wide = xmalloc(command_line.length + sizeof(WCHAR));
	if (!ReadProcessMemory(process, command_line.buffer, wide,
			command_line.length, &bytes_read)
	 || bytes_read != command_line.length)
		goto done;
	wide[command_line.length / sizeof(WCHAR)] = L'\0';
	result = win_wide_to_utf8(wide,
			command_line.length / sizeof(WCHAR));

 done:
	free(wide);
	CloseHandle(process);
	return result;
}

static void win_keep_first_argument(char *cmd)
{
	char *src;
	char *dst = cmd;
	char quote = '\0';

	while (isspace((unsigned char)*cmd))
		cmd++;
	if (*cmd == '"' || *cmd == '\'')
		quote = *cmd++;
	src = cmd;
	while (*src) {
		if ((quote && *src == quote) || (!quote && isspace((unsigned char)*src)))
			break;
		*dst++ = *src++;
	}
	*dst = '\0';
}

static procps_status_t *procps_scan_windows(procps_status_t *sp, int flags)
{
	SYSTEM_PROCESS_INFORMATION *pi;
	char *name;
	unsigned long offset;
	unsigned long ticks_per_second;
	unsigned long long ticks_divisor;

	if (!sp)
		sp = alloc_procps_scan();
	if (!sp->win_proc_buf
	 || sp->win_proc_offset == (unsigned long)-1
	) {
		free_procps_scan(sp);
		return NULL;
	}

	offset = sp->win_proc_offset;
	pi = (SYSTEM_PROCESS_INFORMATION *)((char *)sp->win_proc_buf + offset);
	if (pi->NextEntryOffset)
		sp->win_proc_offset = offset + pi->NextEntryOffset;
	else
		sp->win_proc_offset = (unsigned long)-1;

	free(sp->argv0);
	sp->argv0 = NULL;
	free(sp->exe);
	sp->exe = NULL;
	memset(&sp->vsz, 0, sizeof(*sp) - offsetof(procps_status_t, vsz));

	sp->pid = (uintptr_t)pi->UniqueProcessId;
	sp->ppid = (uintptr_t)pi->InheritedFromUniqueProcessId;
	sp->sid = pi->SessionId;
	sp->uid = getuid();
	sp->gid = getgid();
	sp->state[0] = '?';
	sp->state[1] = ' ';
	sp->state[2] = ' ';
	sp->vsz = (unsigned long)(pi->VirtualMemoryCounters.VirtualSize >> 10);
	sp->rss = (unsigned long)(pi->VirtualMemoryCounters.WorkingSetSize >> 10);

	ticks_per_second = bb_clk_tck();
	ticks_divisor = 10000000ULL / ticks_per_second;
	if (!ticks_divisor)
		ticks_divisor = 1;
	sp->utime = (unsigned long)(pi->UserTime.QuadPart / ticks_divisor);
	sp->stime = (unsigned long)(pi->KernelTime.QuadPart / ticks_divisor);
	{
		FILETIME now_ft;
		ULARGE_INTEGER now;
		unsigned long long age_ms;
		unsigned long long uptime_ms = GetTickCount64();

		GetSystemTimeAsFileTime(&now_ft);
		now.LowPart = now_ft.dwLowDateTime;
		now.HighPart = now_ft.dwHighDateTime;
		age_ms = now.QuadPart > (unsigned long long)pi->CreateTime.QuadPart
			? (now.QuadPart - pi->CreateTime.QuadPart) / 10000
			: 0;
		if (age_ms < uptime_ms)
			sp->start_time = (unsigned long)(
				(uptime_ms - age_ms) * ticks_per_second / 1000
			);
	}
# if ENABLE_FEATURE_PS_ADDITIONAL_COLUMNS
	sp->niceness = 0;
	sp->ruid = sp->uid;
	sp->rgid = sp->gid;
# endif

	if (pi->ImageName.Buffer && pi->ImageName.Length) {
		name = win_wide_to_utf8(pi->ImageName.Buffer,
				pi->ImageName.Length / sizeof(WCHAR));
		safe_strncpy(sp->comm, name ? name : "?", sizeof(sp->comm));
		free(name);
	} else if (sp->pid == 0) {
		safe_strncpy(sp->comm, "System Idle Process", sizeof(sp->comm));
	} else if (sp->pid == 4) {
		safe_strncpy(sp->comm, "System", sizeof(sp->comm));
	} else {
		snprintf(sp->comm, sizeof(sp->comm), "[pid %u]", sp->pid);
	}
	win_process_user(sp->pid, sp->win_user, sizeof(sp->win_user));

	if (flags & PSSCAN_EXE)
		sp->exe = win_process_image_path(sp->pid);
	if (flags & (PSSCAN_ARGV0 | PSSCAN_ARGVN)) {
		sp->argv0 = win_process_command_line(sp->pid);
		if (!sp->argv0)
			sp->argv0 = xstrdup(sp->exe ? sp->exe : sp->comm);
		if (flags & PSSCAN_ARGVN)
			sp->argv_len = strlen(sp->argv0) + 1;
		else
			win_keep_first_argument(sp->argv0);
	}

	return sp;
}
#endif


typedef struct id_to_name_map_t {
	uid_t id;
	char name[USERNAME_MAX_SIZE];
} id_to_name_map_t;

typedef struct cache_t {
	id_to_name_map_t *cache;
	int size;
} cache_t;

static cache_t *cache_user_group;

void FAST_FUNC clear_username_cache(void)
{
	if (cache_user_group) {
		free(cache_user_group[0].cache);
		free(cache_user_group[1].cache);
		free(cache_user_group);
		cache_user_group = NULL;
	}
}

static char* get_cached(int user_group, uid_t id,
			char* FAST_FUNC x2x_utoa(uid_t id))
{
	cache_t *cp;
	int i;

	if (!cache_user_group)
		cache_user_group = xzalloc(sizeof(cache_user_group[0]) * 2);

	cp = &cache_user_group[user_group];

	for (i = 0; i < cp->size; i++)
		if (cp->cache[i].id == id)
			return cp->cache[i].name;
	i = cp->size++;
	cp->cache = xrealloc_vector(cp->cache, 2, i);
	cp->cache[i].id = id;
	/* Never fails. Generates numeric string if name isn't found */
	safe_strncpy(cp->cache[i].name, x2x_utoa(id), sizeof(cp->cache[i].name));
	return cp->cache[i].name;
}
const char* FAST_FUNC get_cached_username(uid_t uid)
{
	return get_cached(0, uid, uid2uname_utoa);
}
const char* FAST_FUNC get_cached_groupname(gid_t gid)
{
	return get_cached(1, gid, gid2group_utoa);
}


#define PROCPS_BUFSIZE 1024

static int read_to_buf(const char *filename, void *buf)
{
	int fd;
	/* open_read_close() would do two reads, checking for EOF.
	 * When you have 10000 /proc/$NUM/stat to read, it isn't desirable */
	ssize_t ret = -1;
	fd = open(filename, O_RDONLY);
	if (fd >= 0) {
		ret = read(fd, buf, PROCPS_BUFSIZE-1);
		close(fd);
	}
	((char *)buf)[ret > 0 ? ret : 0] = '\0';
	return ret;
}

static procps_status_t* FAST_FUNC alloc_procps_scan(void)
{
	procps_status_t* sp = xzalloc(sizeof(procps_status_t));
	unsigned n = bb_getpagesize();
	while (1) {
		n >>= 1;
		if (!n) break;
		sp->shift_pages_to_bytes++;
	}
	sp->shift_pages_to_kb = sp->shift_pages_to_bytes - 10;
#if defined(__CYGWIN__)
	sp->win_proc_buf = win_process_snapshot();
#else
	sp->dir = xopendir("/proc");
#endif
	return sp;
}

void FAST_FUNC free_procps_scan(procps_status_t* sp)
{
#if defined(__CYGWIN__)
	free(sp->win_proc_buf);
#else
	closedir(sp->dir);
#if ENABLE_FEATURE_SHOW_THREADS
	if (sp->task_dir)
		closedir(sp->task_dir);
#endif
#endif
	free(sp->argv0);
	free(sp->exe);
	IF_SELINUX(free(sp->context);)
	free(sp);
}

#if ENABLE_FEATURE_TOPMEM || ENABLE_PMAP
unsigned long long FAST_FUNC fast_strtoull_16(char **endptr)
{
	unsigned char c;
	char *str = *endptr;
	unsigned long long n = 0;

	/* Need to stop on both ' ' and '\n' */
	while ((c = *str++) > ' ') {
		c = ((c|0x20) - '0');
		if (c > 9)
			/* c = c + '0' - 'a' + 10: */
			c = c - ('a' - '0' - 10);
		n = n*16 + c;
	}
	*endptr = str; /* We skip trailing space! */
	return n;
}
#endif

#if ENABLE_FEATURE_FAST_TOP || ENABLE_FEATURE_TOPMEM || ENABLE_PMAP
/* We cut a lot of corners here for speed */
unsigned long FAST_FUNC fast_strtoul_10(char **endptr)
{
	unsigned char c;
	char *str = *endptr;
	unsigned long n = *str - '0';

	/* Need to stop on both ' ' and '\n' */
	while ((c = *++str) > ' ')
		n = n*10 + (c - '0');

	*endptr = str + 1; /* We skip trailing space! */
	return n;
}
# if LONG_MAX < LLONG_MAX
/* For VSZ, which can be very large */
static unsigned long long fast_strtoull_10(char **endptr)
{
	unsigned char c;
	char *str = *endptr;
	unsigned long long n = *str - '0';

	/* Need to stop on both ' ' and '\n' */
	while ((c = *++str) > ' ')
		n = n*10 + (c - '0');

	*endptr = str + 1; /* We skip trailing space! */
	return n;
}
# else
#  define fast_strtoull_10(endptr) fast_strtoul_10(endptr)
# endif

# if ENABLE_FEATURE_FAST_TOP
static long fast_strtol_10(char **endptr)
{
	if (**endptr != '-')
		return fast_strtoul_10(endptr);

	(*endptr)++;
	return - (long)fast_strtoul_10(endptr);
}
# endif

char* FAST_FUNC skip_fields(char *str, int count)
{
	do {
		while (*str++ != ' ')
			continue;
		/* we found a space char, str points after it */
	} while (--count);
	return str;
}
#endif

#if ENABLE_FEATURE_TOPMEM
static NOINLINE void procps_read_smaps(pid_t pid, procps_status_t *sp)
{
	// There is A LOT of /proc/PID/smaps data on a big system.
	// Optimize this for speed, makes "top -m" faster.
//TODO large speedup:
//read /proc/PID/smaps_rollup (cumulative stats of all mappings, much faster)
//and  /proc/PID/maps         to get mapped_ro and mapped_rw (IOW: VSZ,VSZRW)

	FILE *file;
	char filename[sizeof("/proc/%u/smaps") + sizeof(int)*3];
	char buf[PROCPS_BUFSIZE] ALIGN4;

	sprintf(filename, "/proc/%u/smaps", (int)pid);

	file = fopen_for_read(filename);
	if (!file)
		return;

	while (fgets(buf, PROCPS_BUFSIZE, file)) {
		// Each mapping datum has this form:
		// f7d29000-f7d39000 rw-s FILEOFS M:m INODE FILENAME
		// Size:                nnn kB
		// Rss:                 nnn kB
		// .....

		char *tp;
#define bytes4 *(uint32_t*)buf
#define Priv   PACK32_BYTES('P','r','i','v')
#define Shar   PACK32_BYTES('S','h','a','r')
#define SCAN(S, X) \
if (memcmp(buf+4, S, sizeof(S)-1) == 0) { \
	tp = skip_whitespace(buf+4 + sizeof(S)-1); \
	sp->X += fast_strtoul_10(&tp); \
	continue; \
}
		if (bytes4 == Priv) {
			SCAN("ate_Dirty:", private_dirty)
			SCAN("ate_Clean:", private_clean)
		}
		if (bytes4 == Shar) {
			SCAN("ed_Dirty:" , shared_dirty )
			SCAN("ed_Clean:" , shared_clean )
		}
#undef bytes4
#undef Priv
#undef Shar
#undef SCAN
		tp = strchr(buf, '-');
		if (tp) {
			// We reached next mapping - the line of this form:
			// f7d29000-f7d39000 rw-s FILEOFS M:m INODE FILENAME

			char *rwx;
			unsigned long long sz;

			*tp = ' ';
			tp = buf;
			sz = fast_strtoull_16(&tp); // start
			sz = (fast_strtoull_16(&tp) - sz) >> 10; // end - start
			// tp -> "rw-s" string
			rwx = tp;
			// skipping "rw-s FILEOFS M:m INODE "
			tp = skip_whitespace(skip_fields(tp, 4));
			// if not a device memory mapped...
			if (memcmp(tp, "/dev/", 5) != 0    // not "/dev/something"
			 || strcmp(tp + 5, "zero\n") == 0  // or is "/dev/zero" (which isn't a device)
			) {
				if (rwx[1] == 'w')
					sp->mapped_rw += sz;
				else if (rwx[0] == 'r' || rwx[2] == 'x')
					sp->mapped_ro += sz;
				// else: seen "---p" mappings (mmap guard gaps?),
				// do NOT account these as VSZ, they aren't really
			}
			if (strcmp(tp, "[stack]\n") == 0)
				sp->stack += sz;
		}
	}
	fclose(file);
}
#endif

procps_status_t* FAST_FUNC procps_scan(procps_status_t* sp, int flags)
{
#if defined(__CYGWIN__)
	return procps_scan_windows(sp, flags);
#else
	if (!sp)
		sp = alloc_procps_scan();

	for (;;) {
		struct dirent *entry;
		char buf[PROCPS_BUFSIZE];
		long tasknice;
		unsigned pid;
		int n;
		char filename[sizeof("/proc/%u/task/%u/cmdline") + sizeof(int)*3 * 2];
		char *filename_tail;

#if ENABLE_FEATURE_SHOW_THREADS
		if (sp->task_dir) {
			entry = readdir(sp->task_dir);
			if (entry)
				goto got_entry;
			closedir(sp->task_dir);
			sp->task_dir = NULL;
		}
#endif
		entry = readdir(sp->dir);
		if (entry == NULL) {
			free_procps_scan(sp);
			return NULL;
		}
 IF_FEATURE_SHOW_THREADS(got_entry:)
		pid = bb_strtou(entry->d_name, NULL, 10);
		if (errno)
			continue;
#if ENABLE_FEATURE_SHOW_THREADS
		if ((flags & PSSCAN_TASKS) && !sp->task_dir) {
			/* We found another /proc/PID. Do not use it,
			 * there will be /proc/PID/task/PID (same PID!),
			 * so just go ahead and dive into /proc/PID/task. */
			sprintf(filename, "/proc/%u/task", pid);
			/* Note: if opendir fails, we just go to next /proc/XXX */
			sp->task_dir = opendir(filename);
			sp->main_thread_pid = pid;
			continue;
		}
#endif

		/* After this point we can:
		 * "break": stop parsing, return the data
		 * "continue": try next /proc/XXX
		 */

		memset(&sp->vsz, 0, sizeof(*sp) - offsetof(procps_status_t, vsz));

		sp->pid = pid;
		if (!(flags & ~PSSCAN_PID))
			break; /* we needed only pid, we got it */

#if ENABLE_SELINUX
		if (flags & PSSCAN_CONTEXT) {
			if (getpidcon(sp->pid, &sp->context) < 0)
				sp->context = NULL;
		}
#endif

#if ENABLE_FEATURE_SHOW_THREADS
		if (sp->task_dir)
			filename_tail = filename + sprintf(filename, "/proc/%u/task/%u/", sp->main_thread_pid, pid);
		else
#endif
			filename_tail = filename + sprintf(filename, "/proc/%u/", pid);

		if (flags & PSSCAN_UIDGID) {
			struct stat sb;
			if (stat(filename, &sb))
				continue; /* process probably exited */
			/* Effective UID/GID, not real */
			sp->uid = sb.st_uid;
			sp->gid = sb.st_gid;
		}

		/* These are all retrieved from proc/NN/stat in one go: */
		if (flags & (PSSCAN_PPID | PSSCAN_PGID | PSSCAN_SID
			| PSSCAN_COMM | PSSCAN_STATE
			| PSSCAN_VSZ | PSSCAN_RSS
			| PSSCAN_STIME | PSSCAN_UTIME | PSSCAN_START_TIME
			| PSSCAN_TTY | PSSCAN_NICE
			| PSSCAN_CPU)
		) {
			int s_idx;
			char *cp, *comm1;
			int tty;
#if !ENABLE_FEATURE_FAST_TOP
			unsigned long long vsz;
			unsigned long rss;
#endif
			/* see proc(5) for some details on this */
			strcpy(filename_tail, "stat");
			n = read_to_buf(filename, buf);
			if (n < 0)
				continue; /* process probably exited */
			cp = strrchr(buf, ')'); /* split into "PID (cmd" and "<rest>" */
			/*if (!cp || cp[1] != ' ')
				continue;*/
			cp[0] = '\0';
			BUILD_BUG_ON(sizeof(sp->comm) < 16);
			comm1 = strchr(buf, '(');
			/*if (comm1)*/
				safe_strncpy(sp->comm, comm1 + 1, sizeof(sp->comm));

#if !ENABLE_FEATURE_FAST_TOP
			n = sscanf(cp+2,
				"%c %u "               /* state, ppid */
				"%u %u %d %*s "        /* pgid, sid, tty, tpgid */
				"%*s %*s %*s %*s %*s " /* flags, min_flt, cmin_flt, maj_flt, cmaj_flt */
				"%lu %lu "             /* utime, stime */
				"%*s %*s %*s "         /* cutime, cstime, priority */
				"%ld "                 /* nice */
				"%*s %*s "             /* timeout, it_real_value */
				"%lu "                 /* start_time */
				"%llu "                /* vsize - can be very large */
				"%lu "                 /* rss */
# if ENABLE_FEATURE_TOP_SMP_PROCESS
				"%*s %*s %*s %*s %*s %*s " /*rss_rlim, start_code, end_code, start_stack, kstk_esp, kstk_eip */
				"%*s %*s %*s %*s "         /*signal, blocked, sigignore, sigcatch */
				"%*s %*s %*s %*s "         /*wchan, nswap, cnswap, exit_signal */
				"%d"                       /*cpu last seen on*/
# endif
				,
				sp->state, &sp->ppid,
				&sp->pgid, &sp->sid, &tty,
				&sp->utime, &sp->stime,
				&tasknice,
				&sp->start_time,
				&vsz,
				&rss
# if ENABLE_FEATURE_TOP_SMP_PROCESS
				, &sp->last_seen_on_cpu
# endif
				);

			if (n < 11)
				continue; /* bogus data, get next /proc/XXX */
# if ENABLE_FEATURE_TOP_SMP_PROCESS
			if (n == 11)
				sp->last_seen_on_cpu = 0;
# endif

			/* vsz is in bytes and we want kb */
			sp->vsz = vsz >> 10;
			/* vsz is in bytes but rss is in *PAGES*! Can you believe that? */
			sp->rss = rss << sp->shift_pages_to_kb;
			sp->tty_major = (tty >> 8) & 0xfff;
			sp->tty_minor = (tty & 0xff) | ((tty >> 12) & 0xfff00);
#else
/* This costs ~100 bytes more but makes top faster by 20%
 * If you run 10000 processes, this may be important for you */
			sp->state[0] = cp[2];
			cp += 4;
			sp->ppid = fast_strtoul_10(&cp);
			sp->pgid = fast_strtoul_10(&cp);
			sp->sid = fast_strtoul_10(&cp);
			tty = fast_strtoul_10(&cp);
			sp->tty_major = (tty >> 8) & 0xfff;
			sp->tty_minor = (tty & 0xff) | ((tty >> 12) & 0xfff00);
			cp = skip_fields(cp, 6); /* tpgid, flags, min_flt, cmin_flt, maj_flt, cmaj_flt */
			sp->utime = fast_strtoul_10(&cp);
			sp->stime = fast_strtoul_10(&cp);
			cp = skip_fields(cp, 3); /* cutime, cstime, priority */
			tasknice = fast_strtol_10(&cp);
			cp = skip_fields(cp, 2); /* timeout, it_real_value */
			sp->start_time = fast_strtoul_10(&cp);
			/* vsz is in bytes and we want kb */
			sp->vsz = fast_strtoull_10(&cp) >> 10;
			/* vsz is in bytes but rss is in *PAGES*! Can you believe that? */
			sp->rss = fast_strtoul_10(&cp) << sp->shift_pages_to_kb;
# if ENABLE_FEATURE_TOP_SMP_PROCESS
			/* (6): rss_rlim, start_code, end_code, start_stack, kstk_esp, kstk_eip */
			/* (4): signal, blocked, sigignore, sigcatch */
			/* (4): wchan, nswap, cnswap, exit_signal */
			cp = skip_fields(cp, 14);
//FIXME: is it safe to assume this field exists?
			sp->last_seen_on_cpu = fast_strtoul_10(&cp);
# endif
#endif /* FEATURE_FAST_TOP */

#if ENABLE_FEATURE_PS_ADDITIONAL_COLUMNS
			sp->niceness = tasknice;
#endif
			sp->state[1] = ' ';
			sp->state[2] = ' ';
			s_idx = 1;
			if (sp->vsz == 0 && sp->state[0] != 'Z') {
				/* not sure what the purpose of this flag */
				sp->state[1] = 'W';
				s_idx = 2;
			}
			if (tasknice != 0) {
				if (tasknice < 0)
					sp->state[s_idx] = '<';
				else /* > 0 */
					sp->state[s_idx] = 'N';
			}
		}

#if ENABLE_FEATURE_TOPMEM
		if (flags & PSSCAN_SMAPS)
			procps_read_smaps(pid, sp);
#endif /* TOPMEM */
#if ENABLE_FEATURE_PS_ADDITIONAL_COLUMNS
		if (flags & PSSCAN_RUIDGID) {
			FILE *file;

			strcpy(filename_tail, "status");
			file = fopen_for_read(filename);
			if (file) {
				while (fgets(buf, sizeof(buf), file)) {
					char *tp;
#define SCAN_TWO(str, name, statement) \
	if ((tp = is_prefixed_with(buf, str)) != NULL) { \
		tp = skip_whitespace(tp); \
		sscanf(tp, "%u", &sp->name); \
		statement; \
	}
					SCAN_TWO("Uid:", ruid, continue);
					SCAN_TWO("Gid:", rgid, break);
#undef SCAN_TWO
				}
				fclose(file);
			}
		}
#endif /* PS_ADDITIONAL_COLUMNS */
		if (flags & PSSCAN_EXE) {
			strcpy(filename_tail, "exe");
			free(sp->exe);
			sp->exe = xmalloc_readlink(filename);
		}
		/* Note: if /proc/PID/cmdline is empty,
		 * code below "breaks". Therefore it must be
		 * the last code to parse /proc/PID/xxx data
		 * (we used to have /proc/PID/exe parsing after it
		 * and were getting stale sp->exe).
		 */
#if 0 /* PSSCAN_CMD is not used */
		if (flags & (PSSCAN_CMD|PSSCAN_ARGV0)) {
			free(sp->argv0);
			sp->argv0 = NULL;
			free(sp->cmd);
			sp->cmd = NULL;
			strcpy(filename_tail, "cmdline");
			/* TODO: to get rid of size limits, read into malloc buf,
			 * then realloc it down to real size. */
			n = read_to_buf(filename, buf);
			if (n <= 0)
				break;
			if (flags & PSSCAN_ARGV0)
				sp->argv0 = xstrdup(buf);
			if (flags & PSSCAN_CMD) {
				do {
					n--;
					if ((unsigned char)(buf[n]) < ' ')
						buf[n] = ' ';
				} while (n);
				sp->cmd = xstrdup(buf);
			}
		}
#else
		if (flags & (PSSCAN_ARGV0|PSSCAN_ARGVN)) {
			free(sp->argv0);
			sp->argv0 = NULL;
			strcpy(filename_tail, "cmdline");
			n = read_to_buf(filename, buf);
			if (n <= 0)
				break;
			if (flags & PSSCAN_ARGVN) {
				sp->argv_len = n;
				sp->argv0 = xmemdup(buf, n + 1);
				/* sp->argv0[n] = '\0'; - buf has it */
			} else {
				sp->argv_len = 0;
				sp->argv0 = xstrdup(buf);
			}
		}
#endif
		break;
	} /* for (;;) */

	return sp;
#endif
}

int FAST_FUNC bb_process_kill(pid_t pid, int signo)
{
#if defined(__CYGWIN__)
	HANDLE process;
	DWORD access;

	/* Preserve real POSIX signal semantics for Cygwin/MSYS processes. */
	if (kill(pid, signo) == 0)
		return 0;
	if (pid <= 0 || errno != ESRCH)
		return -1;

	if (signo == 0) {
		access = PROCESS_QUERY_LIMITED_INFORMATION;
	} else {
		if (signo != SIGTERM && signo != SIGKILL
		 && signo != SIGINT && signo != SIGHUP && signo != SIGQUIT
		) {
			errno = ENOTSUP;
			return -1;
		}
		access = PROCESS_TERMINATE;
	}

	process = OpenProcess(access, FALSE, (DWORD)pid);
	if (!process) {
		errno = (GetLastError() == ERROR_INVALID_PARAMETER) ? ESRCH : EACCES;
		return -1;
	}
	if (signo != 0 && !TerminateProcess(process, 128 + signo)) {
		CloseHandle(process);
		errno = EACCES;
		return -1;
	}
	CloseHandle(process);
	return 0;
#else
	return kill(pid, signo);
#endif
}

int FAST_FUNC read_cmdline(char *buf, int col, unsigned pid, const char *comm)
{
	int sz;
	char filename[sizeof("/proc/%u/cmdline") + sizeof(int)*3];

#if defined(__CYGWIN__)
	char *cmdline = win_process_command_line(pid);

	if (!cmdline)
		cmdline = win_process_image_path(pid);
	if (!cmdline) {
		snprintf(buf, col, "[%s]", comm ? comm : "?");
		return 0;
	}
	safe_strncpy(buf, cmdline, col);
	free(cmdline);
	for (sz = 0; buf[sz]; sz++) {
		if ((unsigned char)buf[sz] < ' ')
			buf[sz] = '?';
	}
	return 0;
#endif

	sprintf(filename, "/proc/%u/cmdline", pid);
	sz = open_read_close(filename, buf, col - 1);
	if (sz < 0)
		return sz;
	if (sz > 0) {
		const char *program_basename;
		int comm_len;

		buf[sz] = '\0';
		while (--sz >= 0 && buf[sz] == '\0')
			continue;

		/* Find "program" in "[-][/PATH/TO/]program" */
		strchrnul(buf, ' ')[0] = '\0'; /* prevent basename("program foo/bar") = "bar" */
		program_basename = bb_basename(buf[0] == '-' ? buf + 1 : buf);
		/* ^^^ note: must do it *before* replacing argv0's NUL with space */

		/* Prevent stuff like this:
		 *  echo 'sleep 999; exit' >`printf '\ec'`; sh ?c
		 * messing up top and ps output (or worse).
		 * This also replaces NULs with spaces, converting
		 * list of NUL-strings into one string.
		 */
		while (sz >= 0) {
			if ((unsigned char)(buf[sz]) < ' ')
				buf[sz] = (buf[sz] ? /*ctrl*/'?' : /*NUL*/' ');
			sz--;
		}

		/* If comm differs from argv0, prepend "{comm} ".
		 * It allows to see thread names set by prctl(PR_SET_NAME).
		 */
		if (!comm)
			return 0;
		comm_len = strlen(comm);
		/* Why compare up to comm_len, not COMM_LEN-1?
		 * Well, some processes rewrite argv, and use _spaces_ there
		 * while rewriting. (KDE is observed to do it).
		 * I prefer to still treat argv0 "process foo bar"
		 * as 'equal' to comm "process".
		 */
		if (strncmp(program_basename, comm, comm_len) != 0) {
			comm_len += 3;
			if (col > comm_len)
				memmove(buf + comm_len, buf, col - comm_len);
			snprintf(buf, col, "{%s}", comm);
			if (col <= comm_len)
				return 0;
			buf[comm_len - 1] = ' ';
			buf[col - 1] = '\0';
		}
	} else {
		snprintf(buf, col, "[%s]", comm ? comm : "?");
	}
	return 0;
}

/* from kernel:
	//             pid comm S ppid pgid sid tty_nr tty_pgrp flg
	sprintf(buffer,"%d (%s) %c %d  %d   %d  %d     %d       %lu %lu \
%lu %lu %lu %lu %lu %ld %ld %ld %ld %d 0 %llu %lu %ld %lu %lu %lu %lu %lu \
%lu %lu %lu %lu %lu %lu %lu %lu %d %d %lu %lu %llu\n",
		task->pid,
		tcomm,
		state,
		ppid,
		pgid,
		sid,
		tty_nr,
		tty_pgrp,
		task->flags,
		min_flt,
		cmin_flt,
		maj_flt,
		cmaj_flt,
		cputime_to_clock_t(utime),
		cputime_to_clock_t(stime),
		cputime_to_clock_t(cutime),
		cputime_to_clock_t(cstime),
		priority,
		nice,
		num_threads,
		// 0,
		start_time,
		vsize,
		mm ? get_mm_rss(mm) : 0,
		rsslim,
		mm ? mm->start_code : 0,
		mm ? mm->end_code : 0,
		mm ? mm->start_stack : 0,
		esp,
		eip,
the rest is some obsolete cruft
*/
