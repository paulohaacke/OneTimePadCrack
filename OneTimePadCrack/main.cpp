#include <string>
#include <vector>
#include <map>

class Crypto
{
public:
	static std::string xor (std::string str0, std::string str1)
	{
		std::string retStr("");
		int lll = str0.length();
		for (int i = 0; i < str0.length(); i++)
		{
			retStr.push_back(str0[i] ^ str1[i]);
		}
		return retStr;
	}

	static std::string hexToStr(std::string hexASCIIText)
	{
		int len = hexASCIIText.length();
		std::string cText;
		for (int i = 0; i< len; i += 2)
		{
			std::string byte = hexASCIIText.substr(i, 2);
			char chr = (char)(int)strtol(byte.c_str(), NULL, 16);
			cText.push_back(chr);
		}
		return cText;
	}
};

class OneTimePad
{
public:
	static std::string AnalyseCipherXOR(std::vector<std::string> cTexts)
	{
		std::map<std::pair<std::string*, std::string*>, std::string> xorTexts;
		std::vector<std::string>::iterator cTxt;
		for (cTxt = cTexts.begin(); cTxt != cTexts.end(); ++cTxt)
		{
			std::vector<std::string>::iterator cTxtAux;
			for (cTxtAux = cTexts.begin(); cTxtAux != cTexts.end(); ++cTxtAux)
			{
				if (&(*cTxt) != &(*cTxtAux))
				{
					std::pair<std::string*, std::string*> xorIdx = std::make_pair(&(*cTxt), &(*cTxtAux));
					xorTexts[xorIdx] = Crypto :: xor (*cTxt, *cTxtAux);
				}
			}
		}

		std::map<std::string*, std::string> pTexts;
		for (cTxt = cTexts.begin(); cTxt != cTexts.end(); ++cTxt)
		{
			if (pTexts.find(&(*cTxt)) == pTexts.end())
			{
				std::string pTxt((*cTxt).length(), 1);
				pTexts[&(*cTxt)] = pTxt;
			}
			for (int i = 0; i < cTxt->length(); i++)
			{
				int countSpace = 0;
				unsigned char possibleChar = 255;
				std::string* possibleCharIdx;
				std::vector<std::string>::iterator cTxtAux;
				for (cTxtAux = cTexts.begin(); cTxtAux != cTexts.end(); ++cTxtAux)
				{
					if (&(*cTxt) == &(*cTxtAux))
						continue;
					if (pTexts.find(&(*cTxtAux)) == pTexts.end())
					{
						std::string pTxt((*cTxtAux).length(), 1);
						pTexts[&(*cTxtAux)] = pTxt;
					}
					std::pair<std::string*, std::string*> xorIdx = std::make_pair(&(*cTxt), &(*cTxtAux));
					unsigned char charA = ((unsigned char)0xC0); 
					unsigned char charB = xorTexts[xorIdx][i];
					unsigned char charRes = charA & charB;
					if (charRes == ((unsigned char)0x40))
					{
						countSpace++;
						if (countSpace > 1)
						{
							if (countSpace == 2)
							{
								if (pTexts[possibleCharIdx][i] == 1)
									pTexts[possibleCharIdx][i] = possibleChar;
							}
							if (pTexts[&(*cTxtAux)][i] == 1)
								pTexts[&(*cTxtAux)][i] = charB ^ ((unsigned char)0x20);
							if (pTexts[&(*cTxt)][i] == 1)
								pTexts[&(*cTxt)][i] = ((unsigned char)0x20);
						}
						else if (countSpace == 1)
						{
							possibleChar = charB ^ ((unsigned char)0x20);
							possibleCharIdx = &(*cTxtAux);
						}
					}
					else if (charRes == ((unsigned char)0x00))
					{

					}
				}
			}
		}


		return std::string("");
	}
};

int main()
{
	std::vector<std::string> cipherHexTexts = { "BB3A65F6F0034FA957F6A767699CE7FABA855AFB4F2B520AEAD612944A801E",
		"BA7F24F2A35357A05CB8A16762C5A6AAAC924AE6447F0608A3D11388569A1E",
		"A67261BBB30651BA5CF6BA297ED0E7B4E9894AA95E300247F0C0028F409A1E",
		"A57261F5F0004BA74CF4AA2979D9A6B7AC854DA95E305203EC8515954C9D0F",
		"BB3A70F3B91D48E84DF0AB702ECFEEB5BC8C5DA94C301E0BECD241954C831E",
		"A6726DE8F01A50E849EDBC6C7C9CF2B2A88E19FD423E0647ECCB04DD4C9D1E",
		"BC7570BBBF1D46E85AF9AA6C7A9CEFA9E9825CFD5E3A0047F7CD009305A71E"
	};

	std::vector<std::string> cipherTexts(cipherHexTexts.size());
	for (int i = 0; i < cipherHexTexts.size(); i++)
	{
		cipherTexts[i] = Crypto::hexToStr(cipherHexTexts[i]);
	}

	OneTimePad::AnalyseCipherXOR(cipherTexts);

	return 0;
}