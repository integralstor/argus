#ifndef MIGHTY_ARGUS_H
#define MIGHTY_ARGUS_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

#include <stdio.h>
#include <ftw.h>
#include <sys/inotify.h>
#include <mqueue.h>
#include <gmodule.h>
#include <glib.h>


#define PRINT_INFO(fmt, ...)	\
                do { fprintf(out_file, fmt, __VA_ARGS__); \
		} while(0)

#define PRINT_ERROR(fmt, ...)	\
                do { fprintf(err_file, fmt, __VA_ARGS__); \
		} while(0)


struct wd_info {
	int 		wd;
	uint32_t	mask;
	char 		*path;
};

gchar option_context[]	= "[\"/foo/bar\"] Absolute paths please!";
gchar *print_info	= NULL;
gchar *print_error	= NULL;
gchar *watch_path	= NULL;
gchar *ignore_path	= NULL;
gboolean list_root_path = FALSE;
GOptionEntry entries_g[]= {
        { "outfile", 'O', 0, G_OPTION_ARG_STRING, &print_info,
		"File to print output [default:stdout]",
		"/tmp/out.argus" },
        { "errfile", 'E', 0, G_OPTION_ARG_STRING, &print_error,
		"File to print errors [default:stderr]",
		"/tmp/err.argus" },
        { "watch", 'w', 0, G_OPTION_ARG_STRING, &watch_path,
		"Path to watch recursively",
		"/watch/this" },
        { "ignore", 'I', 0, G_OPTION_ARG_STRING, &ignore_path,
		"Path to ignore/remove watch recursively",
		"/ignore/this" },
        { "list-root-paths", 'l', 0, G_OPTION_ARG_NONE, &list_root_path,
		"List root paths being watched", NULL },
        { NULL }
};


struct wd_info 	*new_wd_info();
void 		free_wd_table_info_g(struct wd_info *wdinfop);
void 		watch_each_root_path_g(gpointer root_path, gpointer value,
			gpointer user_data);
void 		list_each_root_path_g(gpointer root_path, gpointer value,
			gpointer data);
gint 		search_tree_g(gpointer pathname, gpointer user_data);

char 		*form_event_path(char *wdpath, uint32_t ilen, char *iname);
int 		dir_tree_add_watch(const char *pathname,
			const struct stat *sbuf,
			int type, struct FTW *ftwb);

int 		argus_reinitiate();
int 		argus_add_watch(const char *pathtoadd, int is_real_path_check,
			int is_root_path);
int 		argus_initial_setup();

int 		cleanup_support_records();
int 		setup_support_records();

int 		destroy_inotify();
int 		initiate_inotify();
int		is_root_path(char *path);
int 		handle_qoverflow();
int		handle_removal(char *removethis);
int 		handle_addition(struct inotify_event *ievent,
			struct wd_info *wdinfop);
int 		handle_move(struct inotify_event *ievent,
			struct wd_info *wdinfop);
int 		handle_ignored(struct inotify_event *ievent,
			struct wd_info *wdinfop);
void 		print_event(struct inotify_event *ievent,
			struct wd_info *wdinfop);
int 		process_inotify_queue(struct epoll_event *evlist);
int 		process_argus_mqueue(struct epoll_event *evlist);

int		mqsend_watch(char *watch_path);
int		mqsend_ignore(char *ignore_path);
int 		mqsend_list_root_path();


#endif
