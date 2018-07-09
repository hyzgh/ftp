#include<map>
#include<pwd.h>
#include<ctime>
#include<cctype>
#include<cstdio>
#include<string>
#include<vector>
#include<cstdlib>
#include<cstring>
#include<iostream>
#include<fcntl.h>
#include<signal.h>
#include<unistd.h>
#include<dirent.h>
#include<sys/stat.h>
#include<sys/wait.h>
#include<sys/types.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<netinet/in.h>
using namespace std;

#define	SA struct sockaddr
#define	SAI struct sockaddr_in
#define NOSET 0
#define PORTMODE 1
#define PASVMODE 2

const int LISTENSIZE = 64;
const int MAX = 1024;
const int DATASIZE = 1460;

struct command {
	string firstArgv;
	string secondArgv;
};

struct state {
	bool logged;
	string username;
	int mode;
	int sockPasv;
	int sockPort;
	int connection;
	SAI clientaddr;
};

const vector<string> allCommands = {
	"USER",
	"PASS",
	"LIST",
	"RETR",
	"STOR",
	"PASV",
	"PWD",
	"CWD",
	"SYST",
	"PORT",
	"QUIT"
};

const vector<string> allAnonymous = {
	"ftp",
	"anonymous"
};

map<string, string> userPass;

int createSocket(int &sock);
int Bind(int &sock, int port);
void getConnection(int &sock, int &connection);
void sendWelcome(int connection);
void initialState(state &sta, int connection);
void parseCommand(command &cmd, char *buff, int len);
int ID(string str);
void user(state &sta, command &cmd);
void initAccounts();
void pass(state &sta, command &cmd);
void list(state &sta, command &cmd);
void retr(state &sta, command &cmd);
void stor(state &sta, command &cmd);
void getIP(int sock, int *IP);
void genPort(int *port);
void pasv(state &sta, command &cmd);
void pwd(state &sta, command &cmd);
void cwd(state &sta, command &cmd);
void syst(state &sta, command &cmd);
string ntos(int *ip);
void initialAddr(SAI &addr, int *port, int *ip);
void getPortAndIP(int *port, int *ip, command cmd);
void port(state &sta, command &cmd);
void unknown(state &sta, command &cmd);
void writeState(state sta, string str);
void responseCommand(state &sta, command &cmd);
void myWait(int signum);
