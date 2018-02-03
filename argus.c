#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "argus.h"


FILE *out_file		= NULL;
FILE *err_file		= NULL;
unsigned long long nwd 	= 0;
int inotify_fd		= -1;
int epoll_fd		= -1;
char mqargus[]		= "/mqargus";
mqd_t mqd		= -1;
uint32_t in_eflags	= 0;

char id_mqargus_watch	= '1';
char id_mqargus_ignore	= '2';
char id_mqargus_list_root_path = '3';

char *cmp_for_each_path = NULL;
GHashTable *wd_table	= NULL;
GHashTable *path_table	= NULL;
GTree *path_tree	= NULL;
GHashTable *root_path_table = NULL;


int mqsend_watch(char *watch_path)
{
	int reterr = 0;
	mqd_t mqwatch = -1;
	mqwatch = mq_open(mqargus, O_WRONLY);
	if (mqwatch == (mqd_t) -1) {
		reterr = errno;
		perror("mq_open");
		return reterr;
	}

	char *mqmsg = NULL;
	mqmsg = calloc(1, strlen(watch_path) + 2);
	if (mqmsg == NULL) {
		reterr = errno;
		perror("calloc");
		return reterr;
	}
	char idstr[1];
	sprintf(idstr, "%c", id_mqargus_watch);
	mqmsg = strncpy(mqmsg, idstr, 2);
	mqmsg = strncat(mqmsg, watch_path, strlen(watch_path) + 1);
	if (mq_send(mqwatch, mqmsg, strlen(mqmsg) + 1, 0) == -1) {
		reterr = errno;
		free(mqmsg);
		perror("mq_send");
		return reterr;
	}
	free(mqmsg);
	if (mq_close(mqwatch)) {
		perror("mq_close");
	}
	return 0;
}


int mqsend_ignore(char *ignore_path)
{
	int reterr = 0;
	mqd_t mqwatch = -1;
	mqwatch = mq_open(mqargus, O_WRONLY);
	if (mqwatch == (mqd_t) -1) {
		reterr = errno;
		perror("mq_open");
		return reterr;
	}

	char *mqmsg = NULL;
	mqmsg = calloc(1, strlen(ignore_path) + 2);
	if (mqmsg == NULL) {
		reterr = errno;
		perror("calloc");
		return reterr;
	}
	char idstr[1];
	sprintf(idstr, "%c", id_mqargus_ignore);
	mqmsg = strncpy(mqmsg, idstr, 2);
	mqmsg = strncat(mqmsg, ignore_path, strlen(ignore_path) + 1);
	if (mq_send(mqwatch, mqmsg, strlen(mqmsg) + 1, 0) == -1) {
		reterr = errno;
		free(mqmsg);
		perror("mq_send");
		return reterr;
	}
	free(mqmsg);
	if (mq_close(mqwatch)) {
		perror("mq_close");
	}
	return 0;
}


int mqsend_list_root_path()
{
	int reterr = 0;
	mqd_t mqlist = -1;
	mqlist = mq_open(mqargus, O_WRONLY);
	if (mqlist == (mqd_t) -1) {
		reterr = errno;
		perror("mq_open");
		return reterr;
	}

	char idstr[1];
	sprintf(idstr, "%c", id_mqargus_list_root_path);
	if (mq_send(mqlist, idstr, strlen(idstr) + 1, 0) == -1) {
		reterr = errno;
		perror("mq_send");
		return reterr;
	}

	if (mq_close(mqlist)) {
		perror("mq_close");
	}
	return 0;
}


struct wd_info *new_wd_info()
{
	struct wd_info *wdinfop;
	wdinfop = calloc(1, sizeof(struct wd_info));
	if (wdinfop == NULL) {
		perror("calloc");
		exit(EXIT_FAILURE);
	}
	wdinfop->wd	= 0;
	wdinfop->mask	= 0;
	wdinfop->path	= NULL;

	return wdinfop;
}


void free_wd_table_info_g(struct wd_info *wdinfop)
{
	free(wdinfop->path);
	free(wdinfop);
}


void print_event(struct inotify_event *ie, struct wd_info *wdinfop)
{
	char *pathp = NULL;
	if (!(ie->mask & IN_Q_OVERFLOW)) {
		pathp = wdinfop->path;
	}

	PRINT_INFO("\n", "");
	PRINT_INFO("          path name = %s; wd = %2d\n", (pathp != NULL) ?
			pathp : "-", ie->wd);
	PRINT_INFO("          ", "");
	if (ie->cookie > 0)
		PRINT_INFO("cookie = %4d; ", ie->cookie);

	PRINT_INFO("event mask = ", "");
	if (ie->mask & IN_ACCESS)
		PRINT_INFO("IN_ACCESS, ", "");
	if (ie->mask & IN_ATTRIB)
		PRINT_INFO("IN_ATTRIB, ", "");
	if (ie->mask & IN_CLOSE_NOWRITE)
		PRINT_INFO("IN_CLOSE_NOWRITE, ", "");
	if (ie->mask & IN_CLOSE_WRITE)
		PRINT_INFO("IN_CLOSE_WRITE, ", "");
	if (ie->mask & IN_CREATE)
		PRINT_INFO("IN_CREATE, ", "");
	if (ie->mask & IN_DELETE)
		PRINT_INFO("IN_DELETE, ", "");
	if (ie->mask & IN_DELETE_SELF)
		PRINT_INFO("IN_DELETE_SELF, ", "");
	if (ie->mask & IN_IGNORED)
		PRINT_INFO("IN_IGNORED, ", "");
	if (ie->mask & IN_ISDIR)
		PRINT_INFO("IN_ISDIR, ", "");
	if (ie->mask & IN_MODIFY)
		PRINT_INFO("IN_MODIFY, ", "");
	if (ie->mask & IN_MOVE_SELF)
		PRINT_INFO("IN_MOVE_SELF, ", "");
	if (ie->mask & IN_MOVED_FROM)
		PRINT_INFO("IN_MOVED_FROM, ", "");
	if (ie->mask & IN_MOVED_TO)
		PRINT_INFO("IN_MOVED_TO, ", "");
	if (ie->mask & IN_OPEN)
		PRINT_INFO("IN_OPEN, ", "");
	if (ie->mask & IN_Q_OVERFLOW)
		PRINT_INFO("IN_Q_OVERFLOW, ", "");
	if (ie->mask & IN_UNMOUNT)
		PRINT_INFO("IN_UNMOUNT, ", "");
	PRINT_INFO("\n", "");
	if (ie->len > 0)
                PRINT_INFO("          name = %s\n", ie->name);

	PRINT_INFO("          nwd: %llu\n", nwd);

}


int dir_tree_add_watch(const char *pathname, const struct stat *sbuf,
		int type, struct FTW *ftwb)
{
	int iwd = -1;
	in_eflags = (IN_ALL_EVENTS | IN_DONT_FOLLOW | IN_ONLYDIR);
	if (type == FTW_DP ) {
		iwd = inotify_add_watch(inotify_fd, pathname,
				in_eflags);
		if (iwd == -1) {
			perror("inotify_add_watch");
			exit(EXIT_FAILURE);
		}

		struct wd_info *wdinfop;
		wdinfop = new_wd_info();
		wdinfop->wd = iwd;
		wdinfop->mask = in_eflags;
		wdinfop->path = strdup(pathname);
		if (wdinfop->path == NULL) {
			perror("strdup");
			exit(EXIT_FAILURE);
		}

		char *strtmp;
		if(g_hash_table_contains(wd_table, GINT_TO_POINTER(iwd))) {
			strtmp = strdup("Tree check: ");
		} else {
			strtmp = strdup("");
			nwd++;
		}
		g_hash_table_replace(wd_table, GINT_TO_POINTER(wdinfop->wd),
				wdinfop);
		g_hash_table_replace(path_table, strdup(wdinfop->path),
				wdinfop);
		g_tree_replace(path_tree, strdup(wdinfop->path),
				GINT_TO_POINTER(wdinfop->wd));

		PRINT_INFO( "nwd: %llu\n", nwd);
		PRINT_INFO( "%sWatching %s with wd %d\n", strtmp,
				wdinfop->path, iwd);
		free(strtmp);
	} 

	return FTW_CONTINUE;
}


void watch_each_root_path_g(gpointer root_path, gpointer value, gpointer data)
{
	int reterr = 0;
	reterr = argus_add_watch((char *)root_path, 0, 0);
	if (reterr) {
		exit(EXIT_FAILURE);
	}
}


void list_each_root_path_g(gpointer root_path, gpointer value, gpointer data)
{
	PRINT_INFO("%s\n", (char *)root_path);
}


gint search_tree_g(gpointer pathname, gpointer user_data)
{
	size_t cmp_size = 0;
	char *tocmp = NULL;
	tocmp = calloc(1, strlen(cmp_for_each_path) + 2);
	if (tocmp == NULL) {
		perror("calloc");
		exit(EXIT_FAILURE);
	}

	tocmp = strncpy(tocmp, cmp_for_each_path, strlen(cmp_for_each_path) + 1);
	tocmp = strncat(tocmp, "/", 2);
	cmp_size = strlen(tocmp);

	int cmp_ret = 0;
	cmp_ret = strncmp(tocmp, (char *)pathname, cmp_size);
	free(tocmp);
	tocmp = NULL;
	if (cmp_ret == 0) {
		return 0;
	} else if (cmp_ret < 0) {
		return -1;
	} else if (cmp_ret > 0) {
		return 1;
	}
	return cmp_ret;
}


char *form_event_path(char *wdpath, uint32_t ilen, char *iname)
{
	char *currpath = NULL;
	currpath = calloc(1, (size_t) (strlen(wdpath) + 1 
				+ ((ilen) ?  ilen : 0) + 2));
	if (currpath == NULL) {
		perror("calloc");
		exit(EXIT_FAILURE);
	}

	currpath = strncpy(currpath, wdpath, strlen(wdpath) + 1);
	currpath = strncat(currpath, "/", 2);
	if (ilen) {
		currpath = strncat(currpath, iname, strlen(iname) + 1);
	}
	return currpath;
}


int argus_add_watch(const char *pathtoadd, int is_real_path_check,
		int is_root_path)
{
	char *addpath = NULL;
	int reterr = 0;

	if (is_real_path_check) {
		addpath = realpath(pathtoadd, NULL);
		if (addpath == NULL) {
			reterr = errno;
			perror("realpath");
			return reterr;
		}
	} else {
		addpath = strdup(pathtoadd);
		if (addpath == NULL) {
			reterr = errno;
			perror("strdup");
			return reterr;
		}
	}

	if (is_root_path) {
		g_hash_table_replace(root_path_table, strdup(addpath), NULL);
	}

	if (nftw(addpath, dir_tree_add_watch, 30,
	    FTW_PHYS | FTW_MOUNT | FTW_DEPTH | FTW_ACTIONRETVAL) == -1) {
		reterr = errno;
		perror("nftw");
		free(addpath);
		return reterr;
	}
	free(addpath);
	return 0;
}


int cleanup_support_records()
{
	g_hash_table_remove_all(wd_table);
	g_hash_table_remove_all(path_table);
	g_tree_destroy(path_tree);
	path_tree = NULL;
	path_tree = g_tree_new_full((GCompareDataFunc)strcmp, NULL,
			(GDestroyNotify)free, NULL);
	return 0;
}


int setup_support_records()
{
	wd_table	= NULL;
	path_table	= NULL;
	path_tree	= NULL;
	root_path_table	= NULL;

	wd_table = g_hash_table_new_full(g_direct_hash, g_direct_equal,
			NULL, (GDestroyNotify)free_wd_table_info_g);
	if (wd_table == NULL) {
		PRINT_ERROR("Hash table fail\n", "");
		return 1;
	}

	path_table = g_hash_table_new_full(g_str_hash, g_str_equal,
			(GDestroyNotify)free, NULL);
	if (path_table == NULL) {
		PRINT_ERROR("Hash table fail\n", "");
		return 1;
	}

	root_path_table = g_hash_table_new_full(g_str_hash, g_str_equal,
			(GDestroyNotify)free, NULL);
	if (root_path_table == NULL) {
		PRINT_ERROR("Hash table fail\n", "");
		return 1;
	}

	path_tree = g_tree_new_full((GCompareDataFunc)strcmp, NULL,
			(GDestroyNotify)free, NULL);
	if (path_tree == NULL) {
		PRINT_ERROR("Tree fail\n", "");
		return 1;
	}

	return 0;
}


int destroy_inotify()
{
	int reterr = 0;
	if (close(inotify_fd) == -1) {
		reterr = errno;
		perror("close");
		return reterr;
	}
	
	if (cleanup_support_records()) {
		return -1;
	}

	if (mq_close(mqd) == -1) {
		reterr = errno;
		perror("mq_close");
		return reterr;
	}
	if (mq_unlink(mqargus) == -1) {
		reterr = errno;
		perror("mq_unlink");
		return reterr;
	}

	return 0;
}


int initiate_inotify() 
{
	int reterr = 0;
	inotify_fd = -1;
	inotify_fd = inotify_init();
	if (inotify_fd == -1) {
		reterr = errno;
		perror("inotify_init");
		return reterr;
	}

	struct epoll_event evtmp = {0};
	evtmp.events	   = EPOLLIN;
	evtmp.data.fd	   = inotify_fd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, inotify_fd, &evtmp) == -1) {
		reterr = errno;
		perror("epoll_ctl");
		return reterr;
	}

	mqd = mq_open(mqargus,
			O_RDWR | O_CREAT | O_NONBLOCK,
			S_IRUSR | S_IWUSR,
			NULL);
	if (mqd == (mqd_t) -1) {
		reterr = errno;
		perror("mq_open");
		return reterr;
	}

	evtmp.data.fd	   = mqd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, mqd, &evtmp) == -1) {
		reterr = errno;
		perror("epoll_ctl");
		return reterr;
	}


	return 0;
}

int argus_reinitiate()
{
	int reterr = 0;

	reterr = destroy_inotify();
	if (reterr) {
		return reterr;
	}

	reterr = initiate_inotify();
	if (reterr) {
		return reterr;
	}

	g_hash_table_foreach(root_path_table, (GHFunc) watch_each_root_path_g,
			NULL);

	return 0;
}


int argus_initial_setup()
{
	int reterr	= 0;

	reterr = setup_support_records();
	if (reterr) {
		return reterr;
	}

	epoll_fd = epoll_create(3);
	if (epoll_fd == -1) {
		reterr = errno;
		perror("epoll_create");
		return reterr;
	}

	reterr = initiate_inotify();
	if (reterr) {
		return reterr;
	}

	return 0;
}


int is_root_path(char *path)
{
	if (!g_hash_table_contains(root_path_table, path)) {
		return 1;
	}
	return 0;
}


int handle_qoverflow()
{
	int reterr = 0;
	reterr = argus_reinitiate();
	if (reterr) {
		PRINT_ERROR("Reinitiation failed!\n", "");
		return reterr;
	}
	return 0;
}


int handle_addition(struct inotify_event *ievent, struct wd_info *wdinfop)
{
	int reterr = 0;
	char *currpath = NULL;
	currpath = form_event_path(wdinfop->path,
			ievent->len,
			ievent->name);

	reterr = argus_add_watch(currpath, 0, 0);
	if (reterr) {
		PRINT_ERROR("%s\n", strerror(reterr));
		return reterr;
	}

	free(currpath);
	currpath = NULL;
	return 0;
}


int handle_ignored(struct inotify_event *ievent, struct wd_info *wdinfop)
{
	char *tp;
	tp = strdup(wdinfop->path);
	if (!g_hash_table_remove(path_table, (const char *)tp)) {
		PRINT_ERROR("Couldnot remove %s from the table\n",
				tp);
	}
	if (!g_hash_table_remove(wd_table, GINT_TO_POINTER(ievent->wd))) {
		PRINT_ERROR("Couldnot remove %d from the table\n",
				ievent->wd);
	}

	g_hash_table_remove(root_path_table, (const char *)tp);

	PRINT_INFO("Removed wd %2d.\n", ievent->wd);
	nwd--;
	free(tp);

	return 0;
}


int handle_move(struct inotify_event *ievent, struct wd_info *wdinfop)
{
	int reterr = 0;
	char *movepath = NULL;
	movepath = form_event_path(wdinfop->path,
				ievent->len, ievent->name);

	reterr = handle_removal(movepath);
	if (reterr) {
		free(movepath);
		return reterr;
	}

	free(movepath);
	movepath = NULL;

	return  0;
}


int handle_removal(char *removethis)
{
	cmp_for_each_path = removethis;

	int reterr = 0;
	struct wd_info *toremwd;
	toremwd = (struct wd_info *)g_hash_table_lookup(path_table,
				cmp_for_each_path);
	if (toremwd == NULL) {
		PRINT_ERROR("Could not lookup path %s\n", cmp_for_each_path);
		cmp_for_each_path = NULL;
		return -1;
	}

	if (!g_tree_remove(path_tree, (const char *)cmp_for_each_path)) {
		PRINT_ERROR("Couldnot remove %s from the tree\n",
				cmp_for_each_path);
	}

	int iwdtmp = -1;
	iwdtmp = inotify_rm_watch(inotify_fd, toremwd->wd);
	if (iwdtmp == -1) {
		reterr = errno;
		perror("inotify_rm_watch");
		cmp_for_each_path = NULL;
		return reterr;
	}
	toremwd = NULL;

	gpointer wdtp = NULL;
	while (1) {
		wdtp = g_tree_search(path_tree,(GCompareFunc)search_tree_g,
					NULL);
		if (wdtp == NULL) {
			break;
		}

		int iwd = -1;
		iwd = inotify_rm_watch(inotify_fd, GPOINTER_TO_INT(wdtp));
		if (iwd == -1) {
			reterr = errno;
			perror("inotify_rm_watch");
			cmp_for_each_path = NULL;
			return reterr;
		}

		struct wd_info *thiswd;
		thiswd = (struct wd_info *)g_hash_table_lookup(wd_table, wdtp);
		if (thiswd == NULL) {
			PRINT_ERROR("Could not lookup wd %d\n",
					GPOINTER_TO_INT(wdtp));
			cmp_for_each_path = NULL;
			return -1;
		}
		if (!g_tree_remove(path_tree, (const char *)thiswd->path)) {
			PRINT_ERROR("Couldnot remove %s from the tree\n",
					thiswd->path);
		}
		thiswd = NULL;
	}
	wdtp = NULL;
	cmp_for_each_path = NULL;

	return 0;
}


int process_argus_mqueue(struct epoll_event *evlist)
{
	ssize_t nrbytes;
	int reterr = 0;
	struct mq_attr attr;
	char *mqmsg = NULL;

	if (evlist->data.fd != mqd) {
		PRINT_ERROR("Incorrect file descriptor\n", "");
		return 1;
	}

	if ((evlist->events & EPOLLERR) || (evlist->events & EPOLLHUP)) {
		reterr = destroy_inotify();
		if (reterr) {
			return reterr;
		}
		return 0;

	} else if (evlist->events & EPOLLIN) {
		if (mq_getattr(mqd, &attr) == -1) {
			reterr = errno;
			perror("mq_getattr");
			return reterr;
		}
		mqmsg = calloc(1, attr.mq_msgsize);
		if (mqmsg == NULL) {
			reterr = errno;
			perror("calloc");
			return reterr;
		}

		nrbytes = mq_receive(mqd, mqmsg, attr.mq_msgsize, NULL);
		if (nrbytes == -1) {
			reterr = errno;
			perror("mq_receive");
			return reterr;
		}

		if (mqmsg[0] == id_mqargus_watch) {
			reterr = argus_add_watch(mqmsg + 1, 1, 1);
			if (reterr) {
				PRINT_ERROR("%s: %s\n", strerror(reterr),
						mqmsg+1);
				return reterr;
			}
		}

		if (mqmsg[0] == id_mqargus_ignore) {
			char *rmpath = NULL;
			rmpath = strdup(mqmsg + 1);
			reterr = handle_removal(rmpath);
			if (reterr) {
				free(rmpath);
				return reterr;
			}
			free(rmpath);
		}

		if (mqmsg[0] == id_mqargus_list_root_path) {
			g_hash_table_foreach(root_path_table,
					(GHFunc) list_each_root_path_g,
					NULL);
		}
	}
	return 0;
}


int process_inotify_queue(struct epoll_event *evlist)
{
	ssize_t nrbytes;
	int reterr = 0;

	if (evlist->data.fd != inotify_fd) {
		PRINT_ERROR("Incorrect file descriptor\n", "");
		return 1;
	}

	if ((evlist->events & EPOLLERR) || (evlist->events & EPOLLHUP)) {
		reterr = destroy_inotify();
		if (reterr) {
			return reterr;
		}
		return 0;

	} else if (evlist->events & EPOLLIN) {
		char *iebuf;
		iebuf = calloc(100,
				sizeof(struct inotify_event) + NAME_MAX + 1);
		if (iebuf == NULL) {
			reterr = errno;
			perror("calloc");
			return  reterr;
		}

		nrbytes = read(evlist->data.fd, iebuf,
				100 *
				(sizeof(struct inotify_event) +
				 NAME_MAX + 1));
		if (nrbytes == -1) {
			reterr = errno;
			perror("read");
			return  reterr;
		}
		if (nrbytes == 0) {
			return -1;
		}

		struct inotify_event *ievent = NULL;
		char *p = NULL;
		for (p = iebuf; p < iebuf + nrbytes; ) {
			ievent = (struct inotify_event *) p;
			p += sizeof(struct inotify_event) + ievent->len;

			struct wd_info *wdinfop = NULL;
			wdinfop = (struct wd_info *)g_hash_table_lookup(
					wd_table,
					GINT_TO_POINTER(ievent->wd));
			if (wdinfop == NULL && !(ievent->mask & IN_Q_OVERFLOW)) {
				PRINT_ERROR("Could not lookup wd %d\n",
						ievent->wd);
				continue;
				// exit(EXIT_FAILURE);
			}

			print_event(ievent, wdinfop);

			if (ievent->mask & IN_Q_OVERFLOW) {
				PRINT_ERROR("Queue overflow, " \
					"reinitiating all watches!\n", "");
				if (handle_qoverflow()) {
					return  -1;
				}
				break;
			}

			if (((ievent->mask & IN_MOVED_TO) &&
				(ievent->mask & IN_ISDIR)) ||
				((ievent->mask & IN_CREATE) &&
				 (ievent->mask & IN_ISDIR))) {
				reterr = handle_addition(ievent, wdinfop);
				if (reterr) {
					return reterr;
				}

			} else if ((ievent->mask & IN_MOVED_FROM) &&
				(ievent->mask & IN_ISDIR)) {
				reterr = handle_move(ievent, wdinfop);
				if (reterr) {
					return reterr;
				}

			}

			if ((ievent->mask & IN_MOVE_SELF)) {
				reterr = is_root_path(wdinfop->path);
				if (reterr == 0) {
					reterr = handle_removal(wdinfop->path);
					if (reterr) {
						return reterr;
					}
				}
			}

			if (ievent->mask & IN_IGNORED) {
				reterr = handle_ignored(ievent, wdinfop);
				if (reterr) {
					return reterr;
				}
			}


		}
		free(iebuf);
		iebuf = NULL;
	}
	return  0;
}


int main(int argc, char *argv[])
{
	int reterr = 0;
	out_file = stdout;
	err_file = stderr;
        GOptionContext *argctx;
        GError *error_g = NULL;

        argctx = g_option_context_new(option_context);
        g_option_context_add_main_entries(argctx, entries_g, NULL);
        if (!g_option_context_parse(argctx, &argc, &argv, &error_g)) {
                PRINT_ERROR("Failed parsing arguments: %s\n",
				error_g->message);
                exit(EXIT_FAILURE);
        }

        if (print_info != NULL) {
                out_file = freopen(print_info, "w", stdout);
                if (out_file == NULL) {
                        perror("freopen");
                        exit(EXIT_FAILURE);
                }
        }
        if (print_error != NULL) {
                err_file = freopen(print_error, "w", stderr);
                if (err_file == NULL) {
                        perror("freopen");
                        exit(EXIT_FAILURE);
                }
        }

	if (watch_path != NULL) {
		if (mqsend_watch((char *)watch_path)) {
			exit(EXIT_FAILURE);
		} else {
			exit(EXIT_SUCCESS);
		}
	}

	if (ignore_path != NULL) {
		if (mqsend_ignore((char *)ignore_path)) {
			exit(EXIT_FAILURE);
		} else {
			exit(EXIT_SUCCESS);
		}
	}

	if (list_root_path) {
		if (mqsend_list_root_path()) {
			exit(EXIT_FAILURE);
		} else {
			exit(EXIT_SUCCESS);
		}
	}

	reterr = argus_initial_setup();
	if (reterr) {
		PRINT_ERROR("Dobby setup fail\n", "");
		exit(EXIT_FAILURE);
	}

	while (1) {
		struct epoll_event *evlist = NULL;
		evlist = calloc(10, sizeof(struct epoll_event));
		if (evlist == NULL) {
			perror("calloc");
			exit(EXIT_FAILURE);
		}

		int nready	= 0;
		nready	= epoll_wait(epoll_fd, evlist, 10, -1);
		if (nready == -1) {
			if (errno == -1) {
				continue;
			} else {
				perror("epoll_wait");
				exit(EXIT_FAILURE);
			}
		}

		int j;
		for (j = 0; j < nready; j++) {
			/*
			PRINT_INFO( " ifd=%d; events: %s%s%s\n",
					evlist[j].data.fd,
					(evlist[j].events & EPOLLIN)	?
					"EPOLLIN  " : "",
					(evlist[j].events & EPOLLERR)	?
					"EPOLLERR " : "",
					(evlist[j].events & EPOLLHUP)	?
					"EPOLLHUP " : "");
					*/
			if (evlist[j].data.fd == inotify_fd) {
				reterr = process_inotify_queue(&evlist[j]);
				if (reterr) {
					exit(EXIT_FAILURE);
				}
			} else if (evlist[j].data.fd == mqd) {
				reterr = process_argus_mqueue(&evlist[j]);
				if (reterr) {
					PRINT_ERROR("Could not process the " \
							"command. Continuing.",
							"");
					/// exit(EXIT_FAILURE);
				}
			}
		}
		free(evlist);
		evlist = NULL;
	}
	PRINT_INFO("All inotify fds closed!\n", "");
	PRINT_INFO("Closing epoll fd\n", "");
	if (close(epoll_fd) == -1) {
		perror("close");
		exit(EXIT_FAILURE);
	}

	g_hash_table_destroy(wd_table);
	wd_table = NULL;
	g_hash_table_destroy(path_table);
	path_table = NULL;
	g_hash_table_destroy(root_path_table);
	root_path_table = NULL;
	g_tree_destroy(path_tree);
	path_tree = NULL;

	if (mq_close(mqd) == -1) {
		perror("mq_close");
	}
	if (mq_unlink(mqargus) == -1) {
		perror("mq_unlink");
	}

	exit(EXIT_SUCCESS);
}
