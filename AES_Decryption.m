% AES_Decryption Function
% This function decrypts a given encrypted hexadecimal string using AES decryption in ECB mode.
% Usage:
%   [decrypted_hex, output_string] = AES_Decryption(encrypted_hex);
% Inputs:
%   - encrypted_hex: A string representing the encrypted data in hexadecimal format.
% Outputs:
%   - decrypted_hex: The decrypted data represented as a hexadecimal string.
%   - output_string: A detailed string containing input and decryption statistics.

% Example Usage:
%   hex_input = '8D4840D6202CC371C32CE0346098';
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


function [decrypted_hex, output_string] = AES_Decryption(encrypted_hex)
    % Remove any whitespace and ensure uppercase
    encrypted_hex = upper(strrep(encrypted_hex, ' ', ''));
    
    % Convert hex to uint8 array
    encrypted_bytes = uint8(hex2dec(reshape(encrypted_hex, 2, [])'));
    
    % Use the same specific 128-bit key (16 bytes)
    key = uint8([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    
    % Create Java AES cipher for decryption
    import javax.crypto.*
    import javax.crypto.spec.*
    cipher = javax.crypto.Cipher.getInstance('AES/ECB/PKCS5Padding');
    secretKey = javax.crypto.spec.SecretKeySpec(key, 'AES');
    cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secretKey);

    % Decrypt the input
    decrypted_bytes = cipher.doFinal(encrypted_bytes);
    
    % Convert decrypted bytes to hex
    decrypted_hex = reshape(dec2hex(decrypted_bytes)', 1, []);
    
    % Calculate statistics
    encrypted_hex_length = length(encrypted_hex);
    encrypted_byte_length = length(encrypted_bytes);
    decrypted_byte_length = length(decrypted_bytes);
    decrypted_hex_length = length(decrypted_hex);
    
    % Prepare the output string
    output_string = sprintf('Input Statistics:\n');
    output_string = [output_string sprintf('  Encrypted hex length: %d characters\n', encrypted_hex_length)];
    output_string = [output_string sprintf('  Encrypted byte length: %d bytes\n', encrypted_byte_length)];
    output_string = [output_string sprintf('Decryption Output:\n')];
    output_string = [output_string sprintf('  Decrypted byte length: %d bytes\n', decrypted_byte_length)];
    output_string = [output_string sprintf('  Decrypted hex length: %d characters\n', decrypted_hex_length)];
    output_string = [output_string sprintf('\nEncrypted (HEX): %s\n', encrypted_hex)];
    output_string = [output_string sprintf('Decrypted (HEX): %s', decrypted_hex)];
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