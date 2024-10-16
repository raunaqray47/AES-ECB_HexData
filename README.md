AES Encryption and Decryption Tool

This repository contains MATLAB functions for AES encryption and decryption, as well as a CSV plotting tool.

Features
- AES encryption in ECB mode
- AES decryption in ECB mode
- CSV plotting for time-amplitude pair


Usage
AES_Encryption Function
The AES_Encryption function encrypts a given hexadecimal string using AES encryption in ECB mode. Input: A string representing the input data in hexadecimal format.
Output: The encrypted data as a hexadecimal string and a detailed output string with encryption statistics.
AES_Decryption Function
The AES_Decryption function decrypts a given encrypted hexadecimal string using AES decryption in ECB mode. Input: A string representing the encrypted data in hexadecimal format.
Output: The decrypted data as a hexadecimal string and a detailed output string with decryption statistics.
PlotCSV Function
The PlotCSV function reads time-amplitude pairs from a CSV file and plots them using MATLAB. Input: A CSV file containing time-amplitude pairs.
Output: A plot of the time-amplitude data.
Example Usage

Encryption:

        Input: 'A1B2C3D4E5F6'
        Call the AES_Encryption function with this input.
        The function will return the encrypted hexadecimal string and encryption statistics.
        
Decryption:
 
        Use the encrypted hexadecimal string from step 1 as input.
        Call the AES_Decryption function with this input.
        The function will return the decrypted hexadecimal string and decryption statistics.
        
CSV Plotting:

        Prepare a CSV file with time-amplitude pairs.
        Call the PlotCSV function with the file path as input.
        The function will generate a plot of the data.

Notes

    The encryption and decryption functions use a fixed 128-bit key for demonstration purposes. In a real-world scenario, you should use a secure key management system. 
    The CSV plotting function assumes a specific format for the input file. Ensure your CSV file matches the expected format.
