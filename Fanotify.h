#pragma once 
#include <errno.h> 
#include <inttypes.h> 
#include <fcntl.h> 
#include <linux/limits.h> 
#include <iostream> 
#include <signal.h> 
#include <stdbool.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <memory> 
#include <string.h> 
#include <sys/select.h> 
#include <sys/time.h> 
#include <sys/types.h>
#include <sys/stat.h> 
#include <unistd.h> 
#include <string.h> 
#include <time.h>
#include <linux/fanotify.h> 
#include <libgen.h>
#include "fanotify-syscalllib.h" 

struct report{
	char *filepath;
	char *filename;
	char *scan_date;	
};

class Fanotify 
{ public: 
	Fanotify() ; 
	~Fanotify() ; 
//选择检测对象 
	void setNotifyObject(std::string path) ; 
//获取句柄 
	int getNotifyFD() ; 
//将fanotify句柄加到select中开始监听 
	void startListen() ; 
//在监控期间可以操作文件 
	void operationFile(int fd) ; 
	char* getpath(int fd);
	char* getNowtime(void) ;	
	report scan_info;
//开始监听函数 
private: 
	std::string paths ; 
//当一些程序试图打开文件的时候，fanotify检测到病给内核发送允许访问标志，当然也可以发送不允许访问标志 
	int handlePerm(const struct fanotify_event_metadata* metadata) ; 
//select监测事件 
	int selectEvent(fd_set* rfd) ; 
//获取文件操作事件类型 
	int getEvent(const struct fanotify_event_metadata* metadata, int len) ; 
//设置检测对象的 
//  std::shared_ptr<epOperation>ep ; 
	int fanFd ; 
	
};




