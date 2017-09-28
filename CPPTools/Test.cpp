#include "Support.h"
#include <iostream>

int main() {
	std::vector<char>* sparse = new std::vector<char>();

	sparse->push_back(1);
	sparse->push_back(2);
	sparse->push_back(3);

	std::cout << sparse->size() << std::endl;

	sparse->erase(sparse->begin(), sparse->begin()+sparse->size());

	std::cout << sparse->size() << std::endl;
	std::cin.ignore();
}