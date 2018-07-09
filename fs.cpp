#include "common.h"

int createSocket(int &sock) {
	return sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

int Bind(int &sock, int port) {
	SAI addr = (SAI) {
		AF_INET, htons(port), (struct in_addr) {INADDR_ANY}
	};
	return bind(sock, (SA*) &addr, sizeof addr);
}

void getConnection(int &sock, int &connection) {
	SAI addr;
	socklen_t len = sizeof(addr);
	connection = accept(sock, (SA*) &addr, &len);
}

void sendWelcome(int connection) {
	char buff[MAX];
	snprintf(buff, MAX, "220 Best welcome to you!\r\n");
	write(connection, buff, strlen(buff));
}

void initialState(state &sta, int connection) {
	sta.logged = false;
	sta.connection = connection;
	sta.username = "";
	sta.mode = NOSET;
	sta.sockPasv = sta.sockPort = 0;
}

void parseCommand(command &cmd, char *buff, int len) {
	cmd.firstArgv = cmd.secondArgv = "";
	int cnt = -1;
	bool first = true;
	while(++cnt < len) {
		if(buff[cnt] == ' ') {
			first = false;
			continue;
		}
		if(iscntrl(buff[cnt]))
			continue;
		if(first)
			cmd.firstArgv += buff[cnt];
		else
			cmd.secondArgv += buff[cnt];
	}
}

int ID(string str) {
	for(int id = 0; id < allCommands.size(); id++) {
		if(str == allCommands[id])
			return id;
	}
	return -1;
}

// 处理USER命令
void user(state &sta, command &cmd) {
	sta.logged = false;
	for(auto str: allAnonymous)
		if(str == cmd.secondArgv) {
			sta.username = cmd.secondArgv;
			writeState(sta, (string)"331 User name okay, need password.\r\n");
			return;
		}
	for(auto i: userPass)
		if(i.first == cmd.secondArgv) {
			sta.username = cmd.secondArgv;
			writeState(sta, (string)"331 User name okay, need password.\r\n");
			return;
		}
	writeState(sta, (string)"501 Invalid username.\r\n");
}

void initAccounts() {
	userPass["hyz"] = "123";
}

// 处理PASS命令
void pass(state &sta, command &cmd) {
	for(auto str: allAnonymous)
		if(str == string(sta.username)) {
			sta.logged = true;

			writeState(sta, (string)"230 Login successful.\r\n");
			return;
		}
	for(auto i: userPass)
		if(i.first == string(sta.username) && userPass[i.first] == string(cmd.secondArgv)) {
			sta.logged = true;
			writeState(sta, (string)"230 Login successful.\r\n");
			return;
		}
	writeState(sta, (string)"501 Invalid username or password.\r\n");
}

// 处理LIST命令
void list(state &sta, command &cmd) {
	if(sta.logged == false) {
		writeState(sta, (string)"530 Please login with USER and PASS.\r\n");
		return;
	}

	// 初始化
	time_t rawtime;
	struct tm *time;
	struct stat statbuf;
	struct dirent *entry;
	char timebuff[80], cwd[MAX], cwd_orig[MAX];

	memset(cwd, 0, MAX);
	memset(cwd_orig, 0, MAX);

	// 切换路径
	getcwd(cwd_orig, MAX);
	if(cmd.secondArgv.length() > 0)
		chdir(cmd.secondArgv.c_str());
	getcwd(cwd, MAX);
	DIR *dp = opendir(cwd);
	int connection;

	// 判断能否打开LIST参数所指路径
	if(!dp) {
		writeState(sta, (string)"550 Failed to open directory.\r\n");
		return;
	}
	if(sta.mode == PORTMODE) {
		//主动模式, 服务器连接客户端
		if(connect(sta.sockPort, (SA*) &sta.clientaddr, sizeof(sta.clientaddr)) < 0) {
			// 可能会因防火墙等原因而连接失败
			printf("Error: Filed to open data connection.\n");
			return;
		}
		connection = sta.sockPort;
	}
	else if(sta.mode == PASVMODE) {
		// 被动模式, 客户端连接服务器
		SAI addr;
		socklen_t len = sizeof addr;
		connection = accept(sta.sockPasv, (SA*) &addr, &len);
		if(connection < 0) {
			cout << "Error: Failed to accept sockPasv." << endl;
			return;
		}
	}
	else {
		writeState(sta, (string)"425 Can't open data connection.\r\n");
		return;
	}

	// 根据RFC959, 一次LIST操作最多能有一个100系列的答复
	// 而且必须有一个100系列的答复, 否则客户端接收不到数据
	writeState(sta, (string)"125 Transfer starting.\r\n");

	while((entry = readdir(dp)) != 0) {
		//读取文件状态
		if(stat(entry->d_name, &statbuf) == -1)
			fprintf(stderr, "Error: Failed to read file status.\n");
		else {
			// 处理文件时间格式
			rawtime = statbuf.st_mtime;
			time = localtime(&rawtime);
			strftime(timebuff, 80 ,"%b %d %H:%M", time);

			// 输出文件状态
			char buff[MAX];
			memset(buff, 0, sizeof buff);
			snprintf(buff, MAX, "%c %8d %s %s\r\n", 
					(entry->d_type==DT_DIR)?'d':'-',
					(int)statbuf.st_size,	//以字节为单位的文件容量
					timebuff,				//时间
					entry->d_name);			//文件名
			write(connection, buff, strlen(buff));
		}
	}

	// 发送226答复码
	writeState(sta, (string)"226 Directory send OK.\r\n");
	sta.mode = NOSET;
	close(connection);
	if(sta.mode == PASVMODE)
		close(sta.sockPasv);
	closedir(dp);
	chdir(cwd_orig);
}

// 处理RETR命令
void retr(state &sta, command &cmd) {
	if(sta.logged == false) {
		writeState(sta, (string)"530 Please login with USER and PASS.\r\n");
		return;
	}

	FILE* fd = NULL;
	int connection;

	fd = fopen(cmd.secondArgv.c_str(), "r");

	if(!fd) {
		writeState(sta, (string)"550 Failed to get file.\r\n");
		return;
	}
	if(sta.mode == PORTMODE) {
		//主动模式, 服务器连接客户端
		if(connect(sta.sockPort, (SA*) &sta.clientaddr, sizeof(sta.clientaddr)) < 0) {
			// 可能会因防火墙等原因而连接失败
			printf("Error: Filed to connect client.");
			return;
		}
		connection = sta.sockPort;
	}
	else if(sta.mode == PASVMODE) {
		//被动模式, 客户端连接服务器
		SAI addr;
		socklen_t len = sizeof addr;
		connection = accept(sta.sockPasv, (SA*) &addr, &len);
	}
	else {
		writeState(sta, (string)"425 Can't open data connection.\r\n");
		return;
	}

	// 根据RFC959, 一次RETR操作最多能有一个100系列的答复
	// 而且必须有一个100系列的答复, 否则客户端接收不到数据
	writeState(sta, (string)"150 About to open data connection.\r\n");

	// 传送文件
	char data[DATASIZE];
	size_t numRead;
	do {
		numRead = fread(data, 1, DATASIZE, fd);
		if(write(connection, data, numRead) < 0)
			perror("Error: Fail to send file.\n");
	} while (numRead > 0);

	// 发送226答复码
	writeState(sta, (string)"226 File send OK.\r\n");
	sta.mode = NOSET;
	close(connection);
	if(sta.mode == PASVMODE)
		close(sta.sockPasv);
	fclose(fd);
	return;
}

// 处理STOR命令
void stor(state &sta, command &cmd) {
	if(sta.logged == false) {
		writeState(sta, (string)"530 Please login with USER and PASS.\r\n");
		return;
	}

	FILE* fp = NULL;
	int connection;

	fp = fopen(cmd.secondArgv.c_str(), "w");
	if(!fp) {
		writeState(sta, (string)"550 Failed to create file.\r\n");
		return;
	}
	if(sta.mode == PORTMODE) {
		//主动模式, 服务器连接客户端
		if(connect(sta.sockPort, (SA*) &sta.clientaddr, sizeof(sta.clientaddr)) < 0) {
			// 可能会因防火墙等原因而连接失败
			printf("Error: Filed to connect client.");
			return;
		}
		connection = sta.sockPort;
	}
	else if(sta.mode == PASVMODE) {
		//被动模式, 客户端连接服务器
		SAI addr;
		socklen_t len = sizeof addr;
		connection = accept(sta.sockPasv, (SA*) &addr, &len);
	}
	else {
		writeState(sta, (string)"425 Can't open data connection.\r\n");
		return;
	}

	// 根据RFC959, 一次STOR操作最多能有一个100系列的答复
	// 而且必须有一个100系列的答复, 否则客户端接收不到数据
	writeState(sta, (string)"125 Data connection already open; transfer starting.\r\n");


	// 传送文件
	int fd = fileno(fp);
	int pipefd[2];
	int res = 1;

	if(pipe(pipefd)==-1)perror("ftp_stor: pipe");
	while((res = splice(connection, 0, pipefd[1], NULL, DATASIZE, SPLICE_F_MORE | SPLICE_F_MOVE)) > 0)
		splice(pipefd[0], NULL, fd, 0, DATASIZE, SPLICE_F_MORE | SPLICE_F_MOVE);
	if(res == -1) {
		perror("ftp_stor: splice");
		return;
	}

	//char data[DATASIZE];
	//int numRead = -1;
	//while((numRead = read(connection, data, DATASIZE)) > 0) {
	//	fwrite(data, numRead, 1, fd);
	//}

	// 发送226答复码
	writeState(sta, (string)"226 File stor OK.\r\n");
	sta.mode = NOSET;
	close(connection);
	if(sta.mode == PASVMODE)
		close(sta.sockPasv);
	close(fd);
	return;
}

void getIP(int sock, int *IP) {
	SAI addr;
	socklen_t len = sizeof(SAI);
	getsockname(sock, (SA*) &addr, &len);

	char* host = inet_ntoa(addr.sin_addr);
	sscanf(host, "%d.%d.%d.%d", &IP[0], &IP[1], &IP[2], &IP[3]);
}

// 随机生成一个大于1024的端口
void genPort(int *port) {
	srand(time(NULL));
	port[0] = 4 + (rand() % 252);
	port[1] = rand() % 256;
}

// 处理PASV命令
void pasv(state &sta, command &cmd) {
	if(sta.logged == false) {
		writeState(sta, (string)"530 Please login with USER and PASS.\r\n");
		return;
	}
	sta.mode = PASVMODE;

	int IP[4], port[2];
	getIP(sta.connection, IP);
	genPort(port);

	createSocket(sta.sockPasv);
	Bind(sta.sockPasv, port[0] * 256 + port[1]);
	listen(sta.sockPasv, LISTENSIZE);

	char buff[MAX];
	memset(buff, 0, sizeof buff);
	snprintf(buff, MAX, "227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)\r\n", IP[0], IP[1], IP[2], IP[3], port[0], port[1]);
	writeState(sta, string(buff));
}

// 处理PWD命令
void pwd(state &sta, command &cmd) {
	if(sta.logged == false) {
		writeState(sta, (string)"530 Please login with USER and PASS.\r\n");
		return;
	}

	char cwd[MAX];
	char buff[MAX];
	memset(buff, 0, sizeof buff);

	if(getcwd(cwd, MAX) != NULL) {
		snprintf(buff, MAX, "250 \"%s\"\r\n", cwd);
		writeState(sta, string(buff));
	}
	else
		writeState(sta, (string)"550 Failed to get pwd.\r\n");
}

// 处理CWD命令
void cwd(state &sta, command &cmd) {
	if(sta.logged == false) {
		writeState(sta, (string)"530 Please login with USER and PASS.\r\n");
		return;
	}
	if(!chdir(cmd.secondArgv.c_str()))
		writeState(sta, (string)"250 Directory successfully changed.\r\n");
	else
		writeState(sta, (string)"550 Failed to change directory.\r\n");
}

// 处理SYST命令
void syst(state &sta, command &cmd) {
	writeState(sta, (string)"215 UNIX\r\n");
}

string ntos(int *ip) {
	string ans = to_string(ip[0]);
	for(int i = 1; i < 4; i++)
		ans += "." + to_string(ip[i]);
	return ans;
}

void initialAddr(SAI &addr, int *port, int *ip) {
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port[0] * 256 + port[1]);
	const char *cstr = ntos(ip).c_str();
	addr.sin_addr.s_addr = inet_addr(cstr);
}

void getPortAndIP(int *port, int *ip, command cmd) {
	const char* secondArgv = cmd.secondArgv.c_str();
	sscanf(secondArgv, "%d,%d,%d,%d,%d,%d", &ip[0], &ip[1], &ip[2], &ip[3], &port[0], &port[1]);
}

// 处理PORT命令
void port(state &sta, command &cmd) {
	if(sta.logged == false) {
		writeState(sta, (string)"530 Please login with USER and PASS.\r\n");
		return;
	}
	sta.mode = PORTMODE;

	int port[2], IP[4];
	getPortAndIP(port, IP, cmd);

	createSocket(sta.sockPort);
	Bind(sta.sockPort, 20);
	initialAddr(sta.clientaddr, port, IP);

	writeState(sta, (string)"200 Port command successful.\r\n");
}

// 处理QUIT命令
void quit(state &sta, command &cmd) {
	while(true)
		if(sta.mode == NOSET) {
			writeState(sta, (string)"221 Service closing control connection.\r\n");
			shutdown(sta.connection, SHUT_RDWR);
			return;
		}
}

void unknown(state &sta, command &cmd) {
	writeState(sta, (string)"500 Command unrecognized.\r\n");
}

void writeState(state sta, string message) {
	const char *cstr = message.c_str();
	write(sta.connection, cstr, strlen(cstr));
}

// 回应命令
void responseCommand(state &sta, command &cmd) {
	cout << cmd.firstArgv << " " << cmd.secondArgv<< endl;
	switch(ID(cmd.firstArgv)) {
		case 0:
			user(sta, cmd); break;
		case 1:
			pass(sta, cmd); break;
		case 2:
			list(sta, cmd); break;
		case 3:
			retr(sta, cmd); break;
		case 4:
			stor(sta, cmd); break;
		case 5:
			pasv(sta, cmd); break;
		case 6:
			pwd(sta, cmd); break;
		case 7:
			cwd(sta, cmd); break;
		case 8:
			syst(sta, cmd); break;
		case 9:
			port(sta, cmd); break;
		case 10:
			quit(sta, cmd); break;
		default:
			unknown(sta, cmd); break;
	}
}

void myWait(int signum) {
	int status;
	wait(&status);
}

int main(int argc, char **argv) {
	// 内置账号
	initAccounts();

	// 创建socket
	int sock;
	if(createSocket(sock) < 0) {
		printf("Error: Fail to create socket.\n");
		return -1;
	}

	// 绑定socket
	if(Bind(sock, 21) < 0) {
		printf("Error: Fail to bind.\n");
		return -1;
	}

	// 令socket进入监听状态
	listen(sock, LISTENSIZE);
	printf("Listening on port 21.\n");

	while(true) {
		// 收到客户端的一个连接请求
		int connection;
		getConnection(sock, connection);

		// 生成子进程
		int pid = fork();
		// 若pid < 0, 表示出现错误
		if(pid < 0) {
			printf("Error: Fail to fork.\n");
			return -1;
		}
		// 若rid == 0, 说明当前位于子进程
		if(pid == 0) {
			// 在子进程中, 首先需要关闭由父亲复制过来的sock
			close(sock);

			// 初始化此次连接状态
			state sta;
			initialState(sta, connection);

			// 向客户端发送220答复码
			sendWelcome(sta.connection);

			// 不断从从客户端读取命令
			int bytesRead;
			char buff[MAX];
			while((bytesRead = read(connection, buff, MAX)) > 0) {
				// 捕获僵尸进程
				signal(SIGCHLD, myWait);

				// 处理读取的指令
				command cmd;
				parseCommand(cmd, buff, bytesRead);
				responseCommand(sta, cmd);
			}
			// 读取命令异常
			if(bytesRead < 0) {
				printf("Error: Command from client is illegal.\n");
				return -1;
			}
			// 结束连接
			printf("Client disconnected.\n");
			return 0;
		}
		// 若pid > 0, 说明当前位于父进程
		if(pid > 0) {
			// 在父进程中, 首先需要关闭属于子进程的connection
			close(connection);
		}
	}

	return 0;
}
