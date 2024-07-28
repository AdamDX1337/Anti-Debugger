#include "Header.h"
#include <iostream>
#include <fstream>
#include <string>


void FileWriter::Send(const std::string& data) {
    std::ofstream outFile("info.txt", std::ios::app); 
    if (outFile.is_open()) {
        outFile << data << std::endl;
        outFile.close();
        //std::cout << "data written to info.txt" << std::endl;
    }
    else {
        //std::cerr << "failed to open file" << std::endl;
    }
}

