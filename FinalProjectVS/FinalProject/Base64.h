#pragma once
#ifndef _BASE64_H_
#define _BASE64_H_

#include <iostream>
#include <string>
using namespace std;

string base64_encode(const string data);
string base64_decode(const string input);

#endif

