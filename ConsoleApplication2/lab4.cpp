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

string CBCEncryptString(const char *instr, const char *passPhrase) // AES CBCģʽ�����ַ�������
{
	std::string outstr;
	byte iv[AES::BLOCKSIZE] = "123456";
	AES::Encryption aesEncryption((byte *)passPhrase, AES::DEFAULT_KEYLENGTH);
	CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
	StreamTransformationFilter cbcEncryptor(
		cbcEncryption,
		new HexEncoder(new StringSink(outstr)),
		BlockPaddingSchemeDef::BlockPaddingScheme::ONE_AND_ZEROS_PADDING,//CBC��Ҫ���
		true);

	cbcEncryptor.Put((byte *)instr, strlen(instr));
	cbcEncryptor.MessageEnd();
	return outstr;
}
string CBCDecryptString(const char *instr, const char *passPhrase)// AES CBCģʽ�����ַ�������
{
	std::string outstr;
	byte iv[AES::BLOCKSIZE] = "123456";
	CBC_Mode<AES >::Decryption cbcDecryption((byte *)passPhrase, AES::DEFAULT_KEYLENGTH, iv);
	HexDecoder decryptor(
		new StreamTransformationFilter(
		cbcDecryption,
		new StringSink(outstr),
		BlockPaddingSchemeDef::BlockPaddingScheme::ONE_AND_ZEROS_PADDING,//CBC��Ҫ���
		true)
		);
	decryptor.Put((byte *)instr, strlen(instr));
	decryptor.MessageEnd();
	return outstr;
}

string CTREncryptString(const char *instr, const byte *passPhrase)// AES CTRģʽ�����ַ�������
{
	string outstr;
	byte iv[AES::BLOCKSIZE] = "102030";//����һ��
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

string CTRDecryptString(const char *instr, const byte *passPhrase)// AES CTRģʽ�����ַ�������
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

// ��ѯ�ı��ļ�����ѯĿ���ַ���src(����)�������ظ��ַ�������λ�õ��������Լ���pwd��ֵ
bool queryFile(string fileName, string src, string &pwd, int &cnt)
{
	fstream mfile(fileName, ios::in);
	pwd = "";
	cnt = 0;
	string str1, str2;

	//cout << "Ҫ���ҵ���: " << src << endl;

	mfile >> str1;//��һ����master password
	cnt++;

	while (!mfile.eof())
	{
		mfile >> str1;
		//cout << "�ļ��е�������: " << str1 << endl;
		if (src == str1)
		{
			mfile >> str2;
			pwd = str2;
			cnt++;
			//cout << "���ҳɹ�! " ;
			//cout << "����: " << cnt << endl;
			mfile.close();
			return true;
		}

		mfile >> str2;
		cnt++;
	}
	//cout << "����ʧ��" << endl;

	mfile.close();
	return false;
}

// ɾ���ı��ļ��еĵ�cnt��
void delRecord(string fileName, int cnt)
{
	cout << "����: " << cnt << endl;
	string line;
	int i = 0;
	fstream fin(fileName, ios::in|ios::out);
	fstream fout("cpy.txt", ios::out);	
	// ����cnt�����������ȫ�����Ƶ��µ���ʱ�ļ�
	while (!fin.eof())
	{
		getline(fin, line);
		i++;
		if (i == cnt)
		{
			cout << "ɾ���� " << i << " ��"<< endl;
			continue;
		}
		fout << line << endl;
	}
	fin.close();
	fout.close();
	// ɾ��ԭ�ļ�
	if (remove(fileName.c_str()))
		printf("Could not delete the file &s \n", fileName.c_str());
	//else printf("OK \n");

	// ������out��ʽ��ԭ�ļ�������һ��ͬ�������ļ���
	fin.open(fileName, ios::out); if (!fin)	cout << "��" << fileName << "ʧ��" << endl;
	fout.open("cpy.txt", ios::in); if (!fout)	cout << "�� cpy.txt " << "ʧ��" << endl;
	// ����ʱ�ļ��������ٴθ��Ƶ������ɵ�ԭ�ļ�
	while (!fout.eof())
	{
		getline(fout, line);
		fin << line << endl;
	}
	fin.close();
	fout.close();

	// ɾ����ʱ�ļ�
	if (remove("cpy.txt"))
		printf("Could not delete the file cpy.txt\n");
	//else printf("OK \n");
}

// �޸��ļ��е�cnt�е�����
void modifyRecord(string fileName, int cnt, string domain, string newStr)
{
	//cout << "����: " << cnt << endl;
	fstream fin(fileName, ios::in | ios::out);
	fstream fout("cpy.txt", ios::out);
	string line;
	int i = 0;
	// ��ԭ�ļ��ĳ��������ݸ��Ƶ��µ���ʱ�ļ������е�cnt�����µ����ݼ��뵽�ļ���
	while (!fin.eof())
	{
		getline(fin, line);
		i++;
		if (i == cnt)
		{
			cout << "�޸ĵ� " << i << " ��"<< endl;
			string alt = domain + " " + newStr; // �µ�һ��
			fout << alt << endl;
			continue;
		}
		fout << line << endl;
	}

	fin.close();
	fout.close();

	// ɾ��ԭ�ļ�
	if (remove(fileName.c_str()))
		printf("Could not delete the file &s \n", fileName.c_str());
	//else printf("OK \n");

	// ��out��ʽ��ԭ�ļ�������һ��ͬ�������ļ���
	fin.open(fileName, ios::out); if (!fin)	cout << "��" << fileName << "ʧ��" << endl;
	fout.open("cpy.txt", ios::in); if (!fout)	cout << "�� cpy.txt " << "ʧ��" << endl;

	// ����ʱ�ļ�������������¸��ƻص�ԭ�ļ�
	while (!fout.eof())
	{
		getline(fout, line);
		fin << line << endl;
	}
	fin.close();
	fout.close();

	// ɾ����ʱ�ļ�
	if (remove("cpy.txt"))
		printf("Could not delete the file cpy.txt\n");
	//else printf("OK \n");
}

// ʹ��PBKDF2ʵ����Կ��չ����
void PBKDF2(const char* pwd, int plen, byte* derivedKey, int derivedKeyLength)
{
	size_t passwordLen = plen;	//�����ֽڳ���
	// ����pwd
	byte *password;
	password = new byte[plen];//����byte����
	memcpy(password, pwd, plen);

	// ������ֵ
	AutoSeededRandomPool rnd;//�����������
	byte salt[32];
	int saltLength = 32;
	rnd.GenerateBlock(salt, 32);//�����������ֵ

	int iterationCount = 512;	// ��������
	int timeInSecond = 30; // ʱ��
	PKCS5_PBKDF2_HMAC<SHA1> pbkdf2; 

	// ����DeriveKey����������Կ��չ
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
		new HexEncoder(//ʹ��HexEncoderʹ���ַ���Դ���׿�
		new StringSink(hexEncoded)
		) // HexEncoder
		); // StringSource

	//cout << "derivedKey: " << hexEncoded << endl;

	rnd.Reseed();
	delete[]password;
}

// HMAC����
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
	cout << "����: " << testp << endl;
	string testc = CTRDecryptString(testp.c_str(), mykey);
	cout << "ԭ��: " << testc << endl;
}

int main() {
	
	char CBCkey[] = "00070309114523810527665813246097";// ������һ��Key
	int CBCKeySize = 32;

	bool enterSuccess = false;
	while (!enterSuccess)
	{
		printf("\n���ã����¼\n");
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
			/* ����ĵ��Ƿ���ڣ���������ڴ���һ���µ��ĵ���
			 ���������master password��Ϊ����û���master password 
			 ��Ҫ���� */
			_file.close();
			_file.open(fileName, ios::out);

			//-------------------------------------------------// 
			// ������ܺ�浽�ļ�
			strEncTxt = CBCEncryptString(masterPasswd.c_str(), CBCkey);
			//cout << "strEncTxt: " << strEncTxt << endl;
			// ���ܺ��passwordд���ļ���һ��
			_file << strEncTxt << endl;
			//-------------------------------------------------// 
			_file.close();
		}
		else
		{
			/* ������֤ 
			 ���������ĵ��е�master password����Ҫ�Ƚ��н��ܣ����û�������Ƿ�һ�£�
			 �����һ���򱨴������ڵ�¼����
			 */
			string filePasswd;
			_file >> filePasswd;/*��һ��Ϊ�����Ժ���û���master password��*/
			//cout << "���ܺ��master password: " << filePasswd << endl;
			_file.close();
			strDecTxt = CBCDecryptString(filePasswd.c_str(), CBCkey);
			//cout << "���ܺ��master password: " << strDecTxt << endl;

			/*
			ÿ���û�һ��txt�ļ����ļ���Ϊ�û������ļ��е�һ��Ϊ�����Ժ���û���master password��
			�ļ���һ��һ�����ݣ�ÿ��������Ҫ������վ���� + ��ϣֵ + �����Ժ������
			*/
			if (masterPasswd == strDecTxt)
			{
				cout << "��¼�ɹ���" << endl;
				enterSuccess = true;
				//break;
				byte derivedKey[16];
				int derivedKeyLength = 16;
				PBKDF2(strDecTxt.c_str(), strDecTxt.length(), derivedKey, derivedKeyLength);// PBKDF2��Կ��չ

				printf("\n========\n");
				// ��¼�ɹ�
				printf("\n\n*********************\tWelcome to Password Manager\t*********************\n\n");

				////////////////////////////////////	�û����ܽ���		///////////////////////////////////
				//printf("�����б�:\t1.��������/����\t\t2.ɾ������/����\n\t\t3.��ѯ����/����\t\t4.�޸�����/����\n\t\t5.���ص�¼����");
				int flag;

				while (enterSuccess)
				{
					printf("--------------------------------------------------------\n");
					printf("�����б�:\t1.��������/����\t\t2.ɾ������/����\n\t\t3.��ѯ����/����\t\t4.�޸�����/����\n\t\t5.���ص�¼����");
					printf("\n--------------------------------------------------------\n");

					printf("\n�����빦����ţ������Ӧ���ܣ� ");
					cin >> flag;
					while (flag < 1 || flag >5)
					{
						printf("\n������1-5�Ĺ������: ");
						cin >> flag;
					}

					string domain, passwd;
					string fPasswd;
					int lineCount = 0;

					/*
					����1��ʵ�ֶ�����վ���� + ��ϣֵ + �����Ժ�����������
					��ʾ�û�������վ����������
					����ĵ����Ƿ�����ͬ��������������򱨴�û������վ���� + ͨ��HMAC����Ĺ�ϣֵ + �����Ժ���������ӵ��ļ�β����������ɹ���Ϣ
					*/
					if (flag == 1)
					{
						printf("\n-----------\t��������/����\t-----------");
						printf("\n��������վ����: ");	cin >> domain;
						// ����HMAC
						string hmac;
						MyHMAC(domain, derivedKey, hmac);
						
						if (queryFile(fileName, hmac, fPasswd, lineCount))
						{
							printf("�����Ѵ���\n");
							continue;
						}
						else
						{
							printf("\n����������: ");		cin >> passwd;
							/*
							û������վ���� + ͨ��HMAC����Ĺ�ϣֵ + �����Ժ���������ӵ��ļ�β����������ɹ���Ϣ
							*/
							//cout << "HMAC�������+��ϣֵ: " << hmac << endl;

							// ����AES����
							string pwdEncodeTxt = CTREncryptString(passwd.c_str(), derivedKey);
							//cout << "AES���ܺ������: " << pwdEncodeTxt << endl;

							fstream fapp(fileName, ios::app);
							string newLine = hmac + " " + pwdEncodeTxt;
							fapp << newLine << endl;
							fapp.close();

							cout << "����ɹ�" << endl;
						}
					}
					else if (flag == 2)
					{
						printf("\n-----------\tɾ������/����\t-----------");
						printf("\n��������վ����: ");	cin >> domain;
						// ����HMAC
						string hmac;
						MyHMAC(domain, derivedKey, hmac);

						if (!queryFile(fileName, hmac, fPasswd, lineCount))
						{
							printf("����������\n");
							continue;
						}
						else
						{
							delRecord(fileName, lineCount);
							cout << "ɾ���ɹ�" << endl;
						}						
					}
					else if (flag == 3)
					{
						printf("\n-----------\t��ѯ����/����\t-----------");
						printf("\n��������վ����: ");	cin >> domain;
						// ����HMAC
						string hmac;
						MyHMAC(domain, derivedKey, hmac);
						if (!queryFile(fileName, hmac, fPasswd, lineCount))
						{
							printf("����������\n");
							continue;
						}
						else
						{
							string pwdDecodeTxt = CTRDecryptString(fPasswd.c_str(), derivedKey);
							cout << "����: " << pwdDecodeTxt << endl;
						}
					}
					else if (flag == 4)
					{
						printf("\n-----------\t�޸�����/����\t-----------");
						printf("\n��������վ����: ");	cin >> domain;
						// ����HMAC
						string hmac;
						MyHMAC(domain, derivedKey, hmac);						

						if (!queryFile(fileName, hmac, fPasswd, lineCount))
						{
							printf("����������\n");
							continue;
						}
						else
						{
							printf("\n����������: ");		cin >> passwd;
							string pwdEncodeTxt = CTREncryptString(passwd.c_str(), derivedKey);
							//cout << "AES���ܺ������: " << pwdEncodeTxt << endl;

							modifyRecord(fileName, lineCount, hmac, pwdEncodeTxt);
							cout << "�޸ĳɹ�" << endl;
						}
					}
					else
					{
						printf("\n\n*********************\t�˳���¼\t*********************\n\n");
						enterSuccess = false;
						break;
					}
				}
			}
			else
			{
				cout << "�������" << endl;
			}
		}
	}


	return 0;
}