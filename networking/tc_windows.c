/* Windows traffic-control state and WinDivert capability probe. */
#include "libbb.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef HANDLE (WINAPI *windivert_open_fn)(const char *, int, int, UINT64);
typedef BOOL (WINAPI *windivert_close_fn)(HANDLE);

struct win_tc_state {
	char dev[128];
	char qdisc[16];
	unsigned long long rate;
	unsigned limit;
	unsigned delay_ms;
	unsigned loss_ppm;
};

static int win_tc_load_driver(void)
{
	HMODULE dll;
	windivert_open_fn open_fn;
	windivert_close_fn close_fn;
	HANDLE handle;

	dll = LoadLibraryA("WinDivert.dll");
	if (!dll)
		return 0;
	open_fn = (windivert_open_fn)GetProcAddress(dll, "WinDivertOpen");
	close_fn = (windivert_close_fn)GetProcAddress(dll, "WinDivertClose");
	if (!open_fn || !close_fn) {
		FreeLibrary(dll);
		return 0;
	}
	/* Opening a harmless outbound handle verifies that the driver is usable. */
	handle = open_fn("outbound", 0, 0, 0);
	if (handle == INVALID_HANDLE_VALUE || !handle) {
		FreeLibrary(dll);
		return 0;
	}
	close_fn(handle);
	FreeLibrary(dll);
	return 1;
}

static void win_tc_state_path(char *path, size_t size, const char *dev)
{
	char safe[128];
	safe_strncpy(safe, dev, sizeof(safe));
	for (char *p = safe; *p; p++)
		if (!isalnum((unsigned char)*p))
			*p = '_';
	snprintf(path, size, ".busybox-tc-%s.state", safe);
}

static int win_tc_save(const struct win_tc_state *state)
{
	char path[256];
	FILE *fp;

	win_tc_state_path(path, sizeof(path), state->dev);
	fp = fopen(path, "w");
	if (!fp)
		return -1;
	fprintf(fp, "dev=%s\nqdisc=%s\nrate=%llu\nlimit=%u\ndelay=%u\nloss=%u\n",
		state->dev, state->qdisc, state->rate, state->limit,
		state->delay_ms, state->loss_ppm);
	fclose(fp);
	return 0;
}

static int win_tc_load(struct win_tc_state *state, const char *dev)
{
	char path[256], key[32], value[256];
	FILE *fp;

	win_tc_state_path(path, sizeof(path), dev);
	fp = fopen(path, "r");
	if (!fp)
		return -1;
	memset(state, 0, sizeof(*state));
	safe_strncpy(state->dev, dev, sizeof(state->dev));
	while (fscanf(fp, "%31[^=]=%255[^\n]\n", key, value) == 2) {
		if (strcmp(key, "qdisc") == 0)
			safe_strncpy(state->qdisc, value, sizeof(state->qdisc));
		else if (strcmp(key, "rate") == 0)
			state->rate = bb_strtoull(value, NULL, 10);
		else if (strcmp(key, "limit") == 0)
			state->limit = bb_strtou(value, NULL, 10);
		else if (strcmp(key, "delay") == 0)
			state->delay_ms = bb_strtou(value, NULL, 10);
		else if (strcmp(key, "loss") == 0)
			state->loss_ppm = bb_strtou(value, NULL, 10);
	}
	fclose(fp);
	return 0;
}

static int win_tc_remove(const char *dev)
{
	char path[256];
	win_tc_state_path(path, sizeof(path), dev);
	return unlink(path);
}

static unsigned long long win_tc_rate(const char *value)
{
	char *end;
	double multiplier = 1.0;
	double number = strtod(value, &end);
	if (end == value || number < 0)
		bb_error_msg_and_die("invalid rate '%s'", value);
	if (strcasecmp(end, "kbit") == 0 || strcasecmp(end, "kbps") == 0)
		multiplier = 1000.0;
	else if (strcasecmp(end, "mbit") == 0 || strcasecmp(end, "mbps") == 0)
		multiplier = 1000000.0;
	else if (*end)
		bb_error_msg_and_die("invalid rate '%s'", value);
	return (unsigned long long)(number * multiplier);
}

int tc_windows_main(int argc, char **argv)
{
	struct win_tc_state state;
	const char *object, *command = "show", *dev = NULL;
	int i;

	if (argc < 2)
		bb_show_usage();
	object = argv[1];
	if (argc > 2 && argv[2][0] != '-')
		command = argv[2];
	for (i = 2; i < argc; i++) {
		if (strcmp(argv[i], "dev") == 0 && i + 1 < argc)
			dev = argv[++i];
	}
	if (!dev)
		dev = "default";

	if (strcmp(command, "show") == 0 || strcmp(command, "list") == 0) {
		if (win_tc_load(&state, dev) != 0) {
			printf("qdisc none dev %s\n", dev);
			return 0;
		}
		printf("qdisc %s dev %s rate %llu limit %u delay %ums loss %.3f%%\n",
			state.qdisc, state.dev, state.rate, state.limit,
			state.delay_ms, state.loss_ppm / 10000.0);
		return 0;
	}

	if (strcmp(object, "qdisc") != 0)
		bb_error_msg_and_die("Windows tc currently supports qdisc only");
	if (strcmp(command, "delete") == 0 || strcmp(command, "del") == 0) {
		if (win_tc_remove(dev) != 0 && errno != ENOENT)
			bb_perror_msg_and_die("cannot remove qdisc state");
		return 0;
	}
	if (strcmp(command, "add") != 0 && strcmp(command, "change") != 0
	 && strcmp(command, "replace") != 0)
		bb_error_msg_and_die("unsupported qdisc command '%s'", command);
	if (!win_tc_load(&state, dev))
		; /* update existing state for change/replace */
	memset(&state, 0, sizeof(state));
	safe_strncpy(state.dev, dev, sizeof(state.dev));
	if (!win_tc_load_driver())
		bb_error_msg_and_die("WinDivert.dll/driver is required for Windows tc");
	for (i = 3; i < argc; i++) {
		if (strcmp(argv[i], "tbf") == 0 || strcmp(argv[i], "netem") == 0
		 || strcmp(argv[i], "pfifo_fast") == 0)
			safe_strncpy(state.qdisc, argv[i], sizeof(state.qdisc));
		else if (strcmp(argv[i], "rate") == 0 && i + 1 < argc)
			state.rate = win_tc_rate(argv[++i]);
		else if (strcmp(argv[i], "limit") == 0 && i + 1 < argc)
			state.limit = bb_strtou(argv[++i], NULL, 10);
		else if (strcmp(argv[i], "delay") == 0 && i + 1 < argc)
			state.delay_ms = bb_strtou(argv[++i], NULL, 10);
		else if (strcmp(argv[i], "loss") == 0 && i + 1 < argc) {
			double loss = strtod(argv[++i], NULL);
			if (loss < 0 || loss > 100)
				bb_error_msg_and_die("invalid loss percentage");
			state.loss_ppm = (unsigned)(loss * 10000.0);
		}
	}
	if (!state.qdisc[0])
		bb_error_msg_and_die("missing qdisc kind");
	if (win_tc_save(&state) != 0)
		bb_perror_msg_and_die("cannot save qdisc state");
	return 0;
}
