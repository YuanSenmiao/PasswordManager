#include "randpool.h"
#include "rsa.h"
#include "hex.h"
#include "files.h"
#include "default.h" 
#include "cryptlib.h"
#include "filters.h"
#include "bench.h"
#include "osrng.h"
#include "hex.h"
#include "modes.h"
#include "files.h"
#include "sha.h"
#include "base64.h"
#include "pwdbased.h"

#include <iostream>
#include <sstream>
#include <cstring>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <time.h> 

using namespace std;
using namespace CryptoPP;

#pragma comment(lib, "cryptlib.lib")

string CBCEncryptString(const char *instr, const char *passPhrase) // AES CBC模式加密字符串函数
{
	std::string outstr;
	byte iv[AES::BLOCKSIZE] = "123456";
	AES::Encryption aesEncryption((byte *)passPhrase, AES::DEFAULT_KEYLENGTH);
	CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
	StreamTransformationFilter cbcEncryptor(
		cbcEncryption,
		new HexEncoder(new StringSink(outstr)),
		BlockPaddingSchemeDef::BlockPaddingScheme::ONE_AND_ZEROS_PADDING,//CBC需要填充
		true);

	cbcEncryptor.Put((byte *)instr, strlen(instr));
	cbcEncryptor.MessageEnd();
	return outstr;
}
string CBCDecryptString(const char *instr, const char *passPhrase)// AES CBC模式解密字符串函数
{
	std::string outstr;
	byte iv[AES::BLOCKSIZE] = "123456";
	CBC_Mode<AES >::Decryption cbcDecryption((byte *)passPhrase, AES::DEFAULT_KEYLENGTH, iv);
	HexDecoder decryptor(
		new StreamTransformationFilter(
		cbcDecryption,
		new StringSink(outstr),
		BlockPaddingSchemeDef::BlockPaddingScheme::ONE_AND_ZEROS_PADDING,//CBC需要填充
		true)
		);
	decryptor.Put((byte *)instr, strlen(instr));
	decryptor.MessageEnd();
	return outstr;
}

string CTREncryptString(const char *instr, const byte *passPhrase)// AES CTR模式加密字符串函数
{
	string outstr;
	byte iv[AES::BLOCKSIZE] = "102030";//必须一致
	AES::Encryption aesEncryption((byte *)passPhrase, AES::DEFAULT_KEYLENGTH);
	CTR_Mode_ExternalCipher::Encryption ctrEncryption(aesEncryption, iv);
	StreamTransformationFilter ctrEncryptor(
		ctrEncryption,
		new HexEncoder(new StringSink(outstr)),
		BlockPaddingSchemeDef::BlockPaddingScheme::NO_PADDING,
		true);

	ctrEncryptor.Put((byte *)instr, strlen(instr));
	ctrEncryptor.MessageEnd();
	return outstr;
}

string CTRDecryptString(const char *instr, const byte *passPhrase)// AES CTR模式解密字符串函数
{
	std::string outstr;
	byte iv[AES::BLOCKSIZE] = "102030";
	CTR_Mode<AES >::Decryption ctrDecryption((byte *)passPhrase, AES::DEFAULT_KEYLENGTH, iv);
	HexDecoder decryptor(
		new StreamTransformationFilter(
		ctrDecryption,
		new StringSink(outstr),
		BlockPaddingSchemeDef::BlockPaddingScheme::NO_PADDING,
		true)
		);
	decryptor.Put((byte *)instr, strlen(instr));
	decryptor.MessageEnd();
	return outstr;
}

// 查询文本文件，查询目标字符串src(域名)，并返回该字符串出现位置的行数，以及给pwd赋值
bool queryFile(string fileName, string src, string &pwd, int &cnt)
{
	fstream mfile(fileName, ios::in);
	pwd = "";
	cnt = 0;
	string str1, str2;

	//cout << "要查找的是: " << src << endl;

	mfile >> str1;//第一行是master password
	cnt++;

	while (!mfile.eof())
	{
		mfile >> str1;
		//cout << "文件中的域名是: " << str1 << endl;
		if (src == str1)
		{
			mfile >> str2;
			pwd = str2;
			cnt++;
			//cout << "查找成功! " ;
			//cout << "行数: " << cnt << endl;
			mfile.close();
			return true;
		}

		mfile >> str2;
		cnt++;
	}
	//cout << "查找失败" << endl;

	mfile.close();
	return false;
}

// 删除文本文件中的第cnt行
void delRecord(string fileName, int cnt)
{
	cout << "行数: " << cnt << endl;
	string line;
	int i = 0;
	fstream fin(fileName, ios::in|ios::out);
	fstream fout("cpy.txt", ios::out);	
	// 将第cnt行以外的内容全部复制到新的临时文件
	while (!fin.eof())
	{
		getline(fin, line);
		i++;
		if (i == cnt)
		{
			cout << "删除第 " << i << " 行"<< endl;
			continue;
		}
		fout << line << endl;
	}
	fin.close();
	fout.close();
	// 删除原文件
	if (remove(fileName.c_str()))
		printf("Could not delete the file &s \n", fileName.c_str());
	//else printf("OK \n");

	// 重新以out方式打开原文件（生成一个同名的新文件）
	fin.open(fileName, ios::out); if (!fin)	cout << "打开" << fileName << "失败" << endl;
	fout.open("cpy.txt", ios::in); if (!fout)	cout << "打开 cpy.txt " << "失败" << endl;
	// 将临时文件的内容再次复制到新生成的原文件
	while (!fout.eof())
	{
		getline(fout, line);
		fin << line << endl;
	}
	fin.close();
	fout.close();

	// 删除临时文件
	if (remove("cpy.txt"))
		printf("Could not delete the file cpy.txt\n");
	//else printf("OK \n");
}

// 修改文件中第cnt行的内容
void modifyRecord(string fileName, int cnt, string domain, string newStr)
{
	//cout << "行数: " << cnt << endl;
	fstream fin(fileName, ios::in | ios::out);
	fstream fout("cpy.txt", ios::out);
	string line;
	int i = 0;
	// 将原文件的除所有内容复制到新的临时文件，其中第cnt行用新的内容加入到文件中
	while (!fin.eof())
	{
		getline(fin, line);
		i++;
		if (i == cnt)
		{
			cout << "修改第 " << i << " 行"<< endl;
			string alt = domain + " " + newStr; // 新的一行
			fout << alt << endl;
			continue;
		}
		fout << line << endl;
	}

	fin.close();
	fout.close();

	// 删除原文件
	if (remove(fileName.c_str()))
		printf("Could not delete the file &s \n", fileName.c_str());
	//else printf("OK \n");

	// 以out方式打开原文件（生成一个同名的新文件）
	fin.open(fileName, ios::out); if (!fin)	cout << "打开" << fileName << "失败" << endl;
	fout.open("cpy.txt", ios::in); if (!fout)	cout << "打开 cpy.txt " << "失败" << endl;

	// 把临时文件里面的内容重新复制回到原文件
	while (!fout.eof())
	{
		getline(fout, line);
		fin << line << endl;
	}
	fin.close();
	fout.close();

	// 删除临时文件
	if (remove("cpy.txt"))
		printf("Could not delete the file cpy.txt\n");
	//else printf("OK \n");
}

// 使用PBKDF2实现密钥扩展函数
void PBKDF2(const char* pwd, int plen, byte* derivedKey, int derivedKeyLength)
{
	size_t passwordLen = plen;	//密码字节长度
	// 拷贝pwd
	byte *password;
	password = new byte[plen];//密码byte数组
	memcpy(password, pwd, plen);

	// 生成盐值
	AutoSeededRandomPool rnd;//随机数产生器
	byte salt[32];
	int saltLength = 32;
	rnd.GenerateBlock(salt, 32);//产生随机数盐值

	int iterationCount = 512;	// 迭代次数
	int timeInSecond = 30; // 时间
	PKCS5_PBKDF2_HMAC<SHA1> pbkdf2; 

	// 调用DeriveKey方法生成密钥扩展
	int c = pbkdf2.DeriveKey(
		derivedKey,
		derivedKeyLength,
		0, 
		password, 
		passwordLen,
		salt, 
		saltLength, 
		iterationCount,
		timeInSecond);
	//cout << "size of derivedKey: " << sizeof(derivedKey) << endl;

	char p[16] = "";
	memcpy(p, password, passwordLen);
	//cout <<"password = "<< p << endl;

	string hexEncoded;
	hexEncoded.clear();
	StringSource(derivedKey, 16, true,
		new HexEncoder(//使用HexEncoder使得字符串源容易看
		new StringSink(hexEncoded)
		) // HexEncoder
		); // StringSource

	//cout << "derivedKey: " << hexEncoded << endl;

	rnd.Reseed();
	delete[]password;
}

// HMAC函数
void MyHMAC(string plain, byte key[], string &encoded)
{
	string mac;

	/*********************************/

	encoded.clear();
	StringSource(key, 16, true,
		new HexEncoder(
		new StringSink(encoded)
		) // HexEncoder
		); // StringSource
	//cout << "key: " << encoded << endl;

	//cout << "plain text: " << plain << endl;

	/*********************************/

	try
	{
		HMAC< SHA256 > hmac(key, 16);

		StringSource(plain, true,
			new HashFilter(hmac,
			new StringSink(mac)
			) // HashFilter      
			); // StringSource
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************/

	encoded.clear();
	StringSource(mac, true,
		new HexEncoder(
		new StringSink(encoded)
		) // HexEncoder
		); // StringSource
	//cout << "hmac: " << encoded << endl;

	/*********************************/

	try
	{
		HMAC< SHA256 > hmac(key, 16);
		const int flags = HashVerificationFilter::THROW_EXCEPTION | HashVerificationFilter::HASH_AT_END;

		StringSource(plain + mac, true,
			new HashVerificationFilter(hmac, NULL, flags)
			); // StringSource

		//cout << "Verified message" << endl;
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}

void test()
{
	// TEST
	byte mykey[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	string testp = CTREncryptString("hello", mykey);
	cout << "密文: " << testp << endl;
	string testc = CTRDecryptString(testp.c_str(), mykey);
	cout << "原文: " << testc << endl;
}

int main() {
	
	char CBCkey[] = "00070309114523810527665813246097";// 随便给定一个Key
	int CBCKeySize = 32;

	bool enterSuccess = false;
	while (!enterSuccess)
	{
		printf("\n您好！请登录\n");
		string fileName;
		printf("Please enter your username and password.\n");
		printf("Username: ");

		string username, masterPasswd;
		cin >> username;
		fileName = username + ".txt";

		printf("Password: ");
		cin >> masterPasswd;

		fstream _file;
		_file.open(fileName, ios::in|ios::out);
		string	strEncTxt;
		string	strDecTxt;

		if (!_file)
		{
			/* 检查文档是否存在，如果不存在创建一个新的文档，
			 并以输入的master password作为这个用户的master password 
			 需要加密 */
			_file.close();
			_file.open(fileName, ios::out);

			//-------------------------------------------------// 
			// 密码加密后存到文件
			strEncTxt = CBCEncryptString(masterPasswd.c_str(), CBCkey);
			//cout << "strEncTxt: " << strEncTxt << endl;
			// 加密后的password写入文件第一行
			_file << strEncTxt << endl;
			//-------------------------------------------------// 
			_file.close();
		}
		else
		{
			/* 密码验证 
			 存在则检查文档中的master password（需要先进行解密）和用户输入的是否一致，
			 如果不一致则报错，保留在登录界面
			 */
			string filePasswd;
			_file >> filePasswd;/*第一行为加密以后的用户的master password，*/
			//cout << "加密后的master password: " << filePasswd << endl;
			_file.close();
			strDecTxt = CBCDecryptString(filePasswd.c_str(), CBCkey);
			//cout << "解密后的master password: " << strDecTxt << endl;

			/*
			每个用户一个txt文件，文件名为用户名，文件中第一行为加密以后的用户的master password，
			文件中一行一组数据，每组数据需要保存网站域名 + 哈希值 + 加密以后的密码
			*/
			if (masterPasswd == strDecTxt)
			{
				cout << "登录成功！" << endl;
				enterSuccess = true;
				//break;
				byte derivedKey[16];
				int derivedKeyLength = 16;
				PBKDF2(strDecTxt.c_str(), strDecTxt.length(), derivedKey, derivedKeyLength);// PBKDF2密钥扩展

				printf("\n========\n");
				// 登录成功
				printf("\n\n*********************\tWelcome to Password Manager\t*********************\n\n");

				////////////////////////////////////	用户功能界面		///////////////////////////////////
				//printf("功能列表:\t1.增加域名/密码\t\t2.删除域名/密码\n\t\t3.查询域名/密码\t\t4.修改域名/密码\n\t\t5.返回登录界面");
				int flag;

				while (enterSuccess)
				{
					printf("--------------------------------------------------------\n");
					printf("功能列表:\t1.增加域名/密码\t\t2.删除域名/密码\n\t\t3.查询域名/密码\t\t4.修改域名/密码\n\t\t5.返回登录界面");
					printf("\n--------------------------------------------------------\n");

					printf("\n请输入功能序号，进入对应功能： ");
					cin >> flag;
					while (flag < 1 || flag >5)
					{
						printf("\n请输入1-5的功能序号: ");
						cin >> flag;
					}

					string domain, passwd;
					string fPasswd;
					int lineCount = 0;

					/*
					功能1：实现对于网站域名 + 哈希值 + 加密以后的密码的增加
					提示用户输入网站域名和密码
					检查文档中是否有相同的域名，如果有则报错；没有则将网站域名 + 通过HMAC算出的哈希值 + 加密以后的密码增加到文件尾部，并输出成功信息
					*/
					if (flag == 1)
					{
						printf("\n-----------\t增加域名/密码\t-----------");
						printf("\n请输入网站域名: ");	cin >> domain;
						// 计算HMAC
						string hmac;
						MyHMAC(domain, derivedKey, hmac);
						
						if (queryFile(fileName, hmac, fPasswd, lineCount))
						{
							printf("域名已存在\n");
							continue;
						}
						else
						{
							printf("\n请输入密码: ");		cin >> passwd;
							/*
							没有则将网站域名 + 通过HMAC算出的哈希值 + 加密以后的密码增加到文件尾部，并输出成功信息
							*/
							//cout << "HMAC后的域名+哈希值: " << hmac << endl;

							// 密码AES加密
							string pwdEncodeTxt = CTREncryptString(passwd.c_str(), derivedKey);
							//cout << "AES加密后的密码: " << pwdEncodeTxt << endl;

							fstream fapp(fileName, ios::app);
							string newLine = hmac + " " + pwdEncodeTxt;
							fapp << newLine << endl;
							fapp.close();

							cout << "插入成功" << endl;
						}
					}
					else if (flag == 2)
					{
						printf("\n-----------\t删除域名/密码\t-----------");
						printf("\n请输入网站域名: ");	cin >> domain;
						// 计算HMAC
						string hmac;
						MyHMAC(domain, derivedKey, hmac);

						if (!queryFile(fileName, hmac, fPasswd, lineCount))
						{
							printf("域名不存在\n");
							continue;
						}
						else
						{
							delRecord(fileName, lineCount);
							cout << "删除成功" << endl;
						}						
					}
					else if (flag == 3)
					{
						printf("\n-----------\t查询域名/密码\t-----------");
						printf("\n请输入网站域名: ");	cin >> domain;
						// 计算HMAC
						string hmac;
						MyHMAC(domain, derivedKey, hmac);
						if (!queryFile(fileName, hmac, fPasswd, lineCount))
						{
							printf("域名不存在\n");
							continue;
						}
						else
						{
							string pwdDecodeTxt = CTRDecryptString(fPasswd.c_str(), derivedKey);
							cout << "密码: " << pwdDecodeTxt << endl;
						}
					}
					else if (flag == 4)
					{
						printf("\n-----------\t修改域名/密码\t-----------");
						printf("\n请输入网站域名: ");	cin >> domain;
						// 计算HMAC
						string hmac;
						MyHMAC(domain, derivedKey, hmac);						

						if (!queryFile(fileName, hmac, fPasswd, lineCount))
						{
							printf("域名不存在\n");
							continue;
						}
						else
						{
							printf("\n请输入密码: ");		cin >> passwd;
							string pwdEncodeTxt = CTREncryptString(passwd.c_str(), derivedKey);
							//cout << "AES加密后的密码: " << pwdEncodeTxt << endl;

							modifyRecord(fileName, lineCount, hmac, pwdEncodeTxt);
							cout << "修改成功" << endl;
						}
					}
					else
					{
						printf("\n\n*********************\t退出登录\t*********************\n\n");
						enterSuccess = false;
						break;
					}
				}
			}
			else
			{
				cout << "密码错误！" << endl;
			}
		}
	}


	return 0;
}