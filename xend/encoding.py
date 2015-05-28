def ansi_encode(plain, value=519):
    if not plain:
        return ''
    result = []
    for letter in plain:
        ansi_raw = ord(letter)
        
        ansi = ansi_raw + 2 * int(value)
        
        if (ansi_raw < 65 or ansi_raw > 90) and letter.islower() == False:
        #print(letter)
            result.append(letter)
        
        elif (ansi_raw < 97 or ansi_raw > 122) and letter.isupper() == False:
        #print(letter)
            result.append(letter)
        
        else:
            while letter.isupper() == True and ansi > 90:
                ansi = -26 + ansi
            
            while letter.isupper() == True and ansi < 65:
                ansi = 26 + ansi
            
            while letter.isupper() == False and ansi > 122:
                ansi = -26 + ansi
            
            while letter.isupper() == False and ansi < 97:
                ansi = 26 + ansi
            
            #print (chr(ansi))
            result.append(chr(ansi))
    return "".join(result)

def ansi_decode(plain, value=519):
    if not plain:
        return ''
    result = []
    for letter in plain:
        ansi_raw = ord(letter)
        
        ansi = ansi_raw - 2 * int(value)
        
        if (ansi_raw < 65 or ansi_raw > 90) and letter.islower() == False:
        #print(letter)
            result.append(letter)
        
        elif (ansi_raw < 97 or ansi_raw > 122) and letter.isupper() == False:
        #print(letter)
            result.append(letter)
        
        else:
            while letter.isupper() == True and ansi > 90:
                ansi = -26 + ansi
            
            while letter.isupper() == True and ansi < 65:
                ansi = 26 + ansi
            
            while letter.isupper() == False and ansi > 122:
                ansi = -26 + ansi
            
            while letter.isupper() == False and ansi < 97:
                ansi = 26 + ansi
            
            #print (chr(ansi))
            result.append(chr(ansi))
    return "".join(result)