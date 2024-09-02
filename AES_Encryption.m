% AES_Encryption Function
% This function encrypts a given hexadecimal string using AES encryption in ECB mode.
% Usage:
%   [encrypted_hex, output_string] = AES_Encryption(hex_input);
% Inputs:
%   - hex_input: A string representing the input data in hexadecimal format.
% Outputs:
%   - encrypted_hex: The encrypted data represented as a hexadecimal string.
%   - output_string: A detailed string containing input and encryption statistics.

% Example Usage:
%   hex_input = 'A1B2C3D4E5F6';
%   [encrypted_hex, encryption_output] = AES_Encryption(hex_input);
%   disp('Encryption Output:');
%   disp(encryption_output);
%   
%   [decrypted_hex, decryption_output] = AES_Decryption(encrypted_hex);
%   disp('Decryption Output:');
%   disp(decryption_output);
%   
%   if strcmpi(hex_input, decrypted_hex)
%       disp('Encryption and decryption successful!');
%   else
%       disp('Error: Decrypted result does not match original input.');
%   end

function [encrypted_hex, output_string] = AES_Encryption(hex_input)
    % Remove any whitespace and ensure uppercase
    hex_input = upper(strrep(hex_input, ' ', ''));
    
    % Convert hex input to uint8 array
    input_bytes = uint8(hex2dec(reshape(hex_input, 2, [])'));
    
    % Use a specific 128-bit key (16 bytes)
    key = uint8([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    
    % Create Java AES cipher
    import javax.crypto.*
    import javax.crypto.spec.*
    cipher = javax.crypto.Cipher.getInstance('AES/ECB/PKCS5Padding');
    secretKey = javax.crypto.spec.SecretKeySpec(key, 'AES');
    cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey);

    % Encrypt the entire input at once
    encrypted_bytes = cipher.doFinal(input_bytes);
    
    % Convert encrypted bytes to hex
    encrypted_hex = reshape(dec2hex(encrypted_bytes)', 1, []);
    
    % Calculate statistics
    input_hex_length = length(hex_input);
    input_byte_length = length(input_bytes);
    encrypted_byte_length = length(encrypted_bytes);
    encrypted_hex_length = length(encrypted_hex);
    
    % Prepare the output string
    output_string = sprintf('Input Statistics:\n');
    output_string = [output_string sprintf('  Hex length: %d characters\n', input_hex_length)];
    output_string = [output_string sprintf('  Byte length: %d bytes\n', input_byte_length)];
    output_string = [output_string sprintf('Encryption Output:\n')];
    output_string = [output_string sprintf('  Encrypted byte length: %d bytes\n', encrypted_byte_length)];
    output_string = [output_string sprintf('  Encrypted hex length: %d characters\n', encrypted_hex_length)];
    output_string = [output_string sprintf('\nUnencrypted (HEX): %s\n', hex_input)];
    output_string = [output_string sprintf('Encrypted (HEX): %s', encrypted_hex)];
end

% Helper function to convert hex to binary
function binary = hexToBinaryVector(hex, order)
    binary = zeros(1, 4*length(hex));
    for i = 1:length(hex)
        binary((i-1)*4+1 : i*4) = hexToBinary(hex(i));
    end
    binary = binary(:)';
    if strcmp(order, 'MSBFirst')
        binary = fliplr(binary);
    end
end

% Helper function to convert a single hex character to binary
function binary = hexToBinary(hexChar)
    binary = de2bi(hex2dec(hexChar), 4, 'left-msb');
end

% Helper function to convert binary vector to hex
function hex = binaryVectorToHex(binary)
    % Pad the binary vector to ensure it's a multiple of 4
    padded_binary = [binary, zeros(1, mod(-length(binary), 4))];
    
    % Reshape into groups of 4 bits
    reshaped = reshape(padded_binary, 4, [])';
    
    % Convert each group to hex
    hex = dec2hex(bin2dec(num2str(reshaped)))';
    
    % Remove any leading zeros
    hex = regexprep(hex, '^0+', '');
end