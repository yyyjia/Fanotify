#include "Fanotify.h"
#include "./md5/md5.h"

#define READ_DATA_SIZE	1024
#define MD5_SIZE		16
#define MD5_STR_LEN		(MD5_SIZE * 2)
#define EICAR_MD5		"69630e4574ec6798239b091cda43dca0"
Fanotify :: Fanotify() {
}

Fanotify :: ~Fanotify() {
    close(fanFd) ;
}


//设置监控对象为目录下的子文件
void Fanotify::setNotifyObject(std::string path) {
   
    //初始化，第一个参数为FAN_CLASS_CONTENT（表示允许接收通知文件事件）另一个值为FAN_CLASS_NOTIF 为默认值。只允许接收事件通知，在一般的监听中，使用FAN_CLASS_CONTENT
    //第二个参数，表示接收到操作文件事件后，本程序对文件的操作为可读可写，因为metadata中的fd为程序操作发生事件的文件的fd，可以直接操作那个文件，操作完后，要关掉。
    fanFd = fanotify_init(FAN_CLASS_CONTENT, O_RDWR) ;
    if(fanFd < 0) {
        std :: cout << __FILE__ << "   " << __LINE__ << "     " << strerror(errno)<< std :: endl ;
        return ;
    }
    std::cout << "初始化完成" << std::endl ;

    //设置在文件open的时候，会通知本程序，同意访问的话，本程序需要给内核发允许访问标志，然后其他程序才能继续访问，否则不能访问
  
    //fanMask |= FAN_ALL_PERM_EVENTS ;
    //FAN_EVENT_ON_CHILD 作用于当前操作目录的所有子文件
    //FAN_MARK_ADD 添加监听事件标志的标志
    int ret = fanotify_mark(fanFd, FAN_MARK_ADD, FAN_OPEN_PERM|FAN_CLOSE|FAN_EVENT_ON_CHILD, AT_FDCWD, path.c_str()) ;
    if(ret < 0) {
        std::cout << __LINE__ <<"   " __FILE__ << "   " << strerror(errno) << std::endl ;
    }
    std::cout << "对象处理完成"<< std::endl ;
}

int Fanotify :: getNotifyFD() {
    return fanFd ;
}

void Fanotify:: startListen() {
    char buf[4096];
    int len = 0 ;
    fd_set rfd ;
    //使用select监听
    FD_ZERO(&rfd) ;
    FD_SET(fanFd, &rfd) ;
	
    std::cout << "开始监听" << std::endl ;
    selectEvent(&rfd) ;
    std:: cout << "发生事件" <<std::endl ;
    while((len = read(fanFd, buf, sizeof(buf))) > 0) {
		
        struct fanotify_event_metadata* metadata ;
        metadata = (fanotify_event_metadata*)buf ;
        if(metadata->fd >= 0) {
            getEvent(metadata, len) ;
        }
        selectEvent(&rfd) ;
    }
    std::cout << strerror(errno) << std :: endl ;
}

int Fanotify:: selectEvent(fd_set* rfd) {
    while(select(fanFd+1, rfd, NULL, NULL, NULL) < 0) {
        if(errno != EINTR) {
            std ::cout << __LINE__ <<  "     " << std::endl ;
            exit(0) ;
        }
    }
    return 1 ;
}

int Fanotify::getEvent(const struct fanotify_event_metadata* metadata, int len) {
	
    while(FAN_EVENT_OK(metadata, len)) {
       //处理matadata
       
        if(metadata->mask&(FAN_OPEN_PERM | FAN_CLOSE)) {
            handlePerm(metadata) ;
        }
        metadata = FAN_EVENT_NEXT(metadata, len) ;
    }   
    return 1 ;
}   

void Fanotify::operationFile(int fd) {
	char *current_path = getpath(fd);
	
	std::cout << "当前文件" << current_path << std::endl;
	remove(current_path);
	std::cout << "删除该病毒文件" << std::endl;
	scan_info.filename = basename(current_path);
	scan_info.filepath = dirname(current_path);
	std::cout << "病毒文件为：" << scan_info.filename << std::endl;
	std::cout << "病毒存放文件夹为：" << scan_info.filepath << std::endl;
    close(fd) ;
}

int Fanotify::handlePerm(const struct fanotify_event_metadata *metadata) {
    struct fanotify_response response_struct;
    int ret;
	char md5_str[MD5_STR_LEN + 1];
 	response_struct.fd = metadata->fd;
	char *current_path = getpath(metadata->fd);
	
	if (strcmp(current_path, "/home/yj/test/mini_project/dir/m1") ){
			Compute_file_md5(metadata->fd, md5_str);
	
			bool flag = strcmp(EICAR_MD5, md5_str);
			if(flag){
		
				response_struct.response = FAN_ALLOW;	
			}else{
				if(scan_info.scan_date != NULL && scan_info.filename != NULL && scan_info.filepath != NULL){
					scan_info.scan_date = NULL;
					scan_info.filename = NULL;
					scan_info.filename = NULL;
				}
				std::cout << "这是一个病毒文件" << std::endl;
				scan_info.scan_date = getNowtime();
				std::cout << "扫描时间为：" << scan_info.scan_date << std::endl;
				operationFile(metadata->fd) ;
				response_struct.response = FAN_DENY;	
			}
	
	}else{
			//执行下面的内容，一直到write前面;	
			response_struct.response = FAN_ALLOW;
	}
	

	
    ret = write(fanFd, &response_struct, sizeof(response_struct));
    if (ret < 0)
        return ret;

    return 0;
}

char* Fanotify::getNowtime(void) 
{
	static char s[30]={0};
    char YMD[15] = {0};
    char HMS[10] = {0};
    time_t current_time;
    struct tm* now_time;

    char *cur_time = (char *)malloc(21*sizeof(char));
    time(&current_time);
    now_time = localtime(&current_time);

    strftime(YMD, sizeof(YMD), "%F ", now_time);
    strftime(HMS, sizeof(HMS), "%T", now_time);
    
    strncat(cur_time, YMD, 11);
    strncat(cur_time, HMS, 8);

	memcpy(s, cur_time, strlen(cur_time)+1);
    free(cur_time);

    cur_time = NULL;

    return s;
}

char* Fanotify::getpath(int fd)
{
	static char path[PATH_MAX] ;
    int pathLen ;
	sprintf(path, "/proc/self/fd/%d", fd) ;
   	pathLen = readlink(path, path, sizeof(path)-1) ;
	    
	if(pathLen < 0) {
    	std :: cout << __LINE__ << "     " << __FILE__ << std::endl ;
        exit(1) ;
	}
	
    path[pathLen] = '\0' ;
	return path;
}


