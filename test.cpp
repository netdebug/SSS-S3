// test.cpp - written and placed in the public domain by Wei Dai
#define _CRT_SECURE_NO_DEPRECATE
#define CRYPTOPP_DEFAULT_NO_DLL
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
//#include "dll.h"
#include "cryptopp/md5.h"
#include "cryptopp/ripemd.h"
#include "cryptopp/rng.h"
#include "cryptopp/gzip.h"
#include "cryptopp/default.h"
#include "cryptopp/randpool.h"
#include "cryptopp/ida.h"
#include "cryptopp/base64.h"
#include "cryptopp/socketft.h"
#include "cryptopp/wait.h"
#include "cryptopp/factory.h"
#include "cryptopp/whrlpool.h"
#include "cryptopp/tiger.h"
//#include "validate.h"
#include "cryptopp/bench.h"
#include "cryptopp/randpool.h"
#include "cryptopp/hex.h"
#include <iostream>
#include <time.h>
#include <stdio.h>
#ifdef CRYPTOPP_WIN32_AVAILABLE
#include <windows.h>
#endif
#if defined(USE_BERKELEY_STYLE_SOCKETS) && !defined(macintosh)
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif
#if (_MSC_VER >= 1000)
#include <crtdbg.h> // for the debug heap
#endif
#if defined(__MWERKS__) && defined(macintosh)
#include <console.h>
#endif
#ifdef __BORLANDC__
#pragma comment(lib, "cryptlib_bds.lib")
#pragma comment(lib, "ws2_32.lib")
#endif
USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)
const int MAX_PHRASE_LENGTH=250; 


void SecretShareFile(int threshold, int nShares, const char *filename, const char *seed)
{
	assert(nShares<=1000);
	RandomPool rng;
	rng.IncorporateEntropy((byte *)seed, strlen(seed));
	ChannelSwitch *channelSwitch;
	FileSource source(filename, false, new SecretSharing(rng, threshold, nShares, channelSwitch = new ChannelSwitch));
	/*SecretSharing *sss = new SecretSharing(rng, threshold, nShares, channelSwitch = new ChannelSwitch);
	string pt = "abcd";
	const unsigned char *c = (const unsigned char*) pt.c_str();
	sss->Put(c, 5, true);
	sss->MessageEnd(-1, true);
	bool mesgs = sss->AnyMessages();
	cout<<mesgs<<endl;
	lword max_ret = sss->MaxRetrievable();
	cout<<max_ret<<endl;
	*/
	vector_member_ptrs<FileSink> fileSinks(nShares);
	vector_member_ptrs<ArraySink> sinks(nShares);
	string channel;
	std::vector<string> buf(nShares);
	for (int i=0; i<nShares; i++)
	{
		char extension[5] = ".000";
		extension[1]='0'+byte(i/100);
		extension[2]='0'+byte((i/10)%10);
		extension[3]='0'+byte(i%10);
		fileSinks[i].reset(new FileSink((string(filename)+extension).c_str()));
		sinks[i].reset(new ArraySink((byte *) buf.at(i).c_str(), buf.at(i).length()));
		channel = WordToString<word32>(i);
		//cout<<channel.data()<<endl;
		fileSinks[i]->Put((byte *)channel.data(), 4);
		sinks[i]->Put((byte *) channel.data(), 4);
		channelSwitch->AddRoute(channel, *fileSinks[i], DEFAULT_CHANNEL);
	}
	std::istream *is = source.GetStream();
	//cout<<is->rdbuf();
	/*char cs = is->get();
	while(is) {
		//cout<<cs;
		cs = is->get();
	}*/
	source.PumpAll();
	cout<<buf.at(0)<<endl;
} 

void SecretRecoverFile(int threshold, const char *outFilename, char *const *inFilenames)
{
	assert(threshold<=1000);
	SecretRecovery recovery(threshold, new FileSink(outFilename));
	vector_member_ptrs<FileSource> fileSources(threshold);
	SecByteBlock channel(4);
	int i;
	for (i=0; i<threshold; i++)
	{
		cout<<inFilenames[i]<<endl;
		fileSources[i].reset(new FileSource(inFilenames[i], false));
		fileSources[i]->Pump(4);
		fileSources[i]->Get(channel, 4);
		fileSources[i]->Attach(new ChannelSwitch(recovery, string((char *)channel.begin(), 4)));
	}
	while (fileSources[0]->Pump(256)) {
	for (i=1; i<threshold; i++)
		fileSources[i]->Pump(256);
	for (i=0; i<threshold; i++)
		fileSources[i]->PumpAll();
	}
} 

void EncryptFile(const char *in, const char *out, const char *passPhrase)
{
	FileSource f(in, true, new DefaultEncryptorWithMAC(passPhrase, new FileSink(out)));
}

void DecryptFile(const char *in, const char *out, const char *passPhrase)
{
	FileSource f(in, true, new DefaultDecryptorWithMAC(passPhrase, new FileSink(out)));
} 

SecByteBlock HexDecodeString(const char *hex)
{
	StringSource ss(hex, true, new HexDecoder);
	SecByteBlock result((size_t)ss.MaxRetrievable());
	ss.Get(result, result.size());
	return result;
} 
/*
void AES_CTR_Encrypt(const char *hexKey, const char *hexIV, const char *infile, const char *outfile)
{
	SecByteBlock key = HexDecodeString(hexKey);
	SecByteBlock iv = HexDecodeString(hexIV);
	CTR_Mode<AES>::Encryption aes(key, key.size(), iv);
	FileSource(infile, true, new StreamTransformationFilter(aes, new FileSink(outfile)));
} 
*/

int main(int argc, char **args) {
	if(argc != 4) {
		cout<<"Usage: ./scube <filename> <threshold> <nshares>"<<endl;
		return 1;
	}
	
	const char* filename = (const char*) args[1];
	int threshold = atoi(args[2]);
	int nshares = atoi(args[3]);
	char const *inFilenames[6] = { "test.cpp.000", "test.cpp.001", "test.cpp.002"};//,"test.cpp.003","test.cpp.004","test.cpp.005"};
	SecretShareFile(threshold, nshares, "test.cpp", "x");
	//SecretShareFile(3, 5, "test.cpp", "x");
	//SecretRecoverFile(threshold, "lord.cpp", (char* const*) inFilenames);
	//SecretRecoverFile(3, "lord.cpp", (char* const*) inFilenames);
	FILE *fd = fopen("test.cpp", "r");
	char *in = (char *) malloc(512);
	fread(in, 1, 512, fd);
	char *out = (char *) malloc(512);
	fread(out, 1, 512, fd);
	//EncryptFile(in, out, "passphrase");
	//cout<<out<<endl;
	//AES_CTR_Encrypt("abcd12345678ababababffffffffffff", "ababa", in, out);
	return 1;
}

