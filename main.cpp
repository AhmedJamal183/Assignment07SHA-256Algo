#include <iostream>
#include <fstream>
#include <string>
#include "sha256.h" //header file
 
using namespace std;

int main()
{
    ifstream inputFile("MarkComplete.txt");
    string textInput( (istreambuf_iterator<char>(inputFile) ), (istreambuf_iterator<char>()) );
    string hashOutput = sha256(textInput);
    cout << "SHA-256 Encrypted Output : " << hashOutput << endl;   
    return 0;
}
