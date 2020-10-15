def sha1(inp):
    
    def preprocess(inp):
        '''
        modify input
        '''
        bits = ""
    
        for i in range(len(inp)):
            bits += '{0:08b}'.format(ord(inp[i]))

        inp_len = len(bits)
        
        bits += "1"
        
        while len(bits)%512 != 448:
            bits += "0"
        
        bits +='{0:064b}'.format(inp_len)
        
        return bits
        
    
    def leftRotate32(num, no_of_times):
        '''
        returns circular left shift of 32 bit number
        '''
        return ((num << no_of_times) | (num >> (32 - no_of_times))) & 0xffffffff

    
    '''
    in this function actual implementation of SHA is done
    to know about algorith check the following link:
    https://brilliant.org/wiki/secure-hashing-algorithms/#
    '''
    
    bits = preprocess(inp)  #  create bits array

    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0


    def getChunks(l, n):
        return [l[i:i+n] for i in range(0, len(l), n)]


    for chunk in getChunks(bits, 512):
        words = getChunks(chunk, 32)
        w = [0]*80
        for n in range(0, 16):
            w[n] = int(words[n], 2)

        for i in range(16, 80):
            w[i] = leftRotate32((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1)  

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for i in range(0, 80) :
            if 0 <= i and i < 20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i and i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i and i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i and i < 80:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = leftRotate32(a, 5) + f + e + k + w[i] & 0xffffffff
            e = d
            d = c
            c = leftRotate32(b, 30)
            b = a
            a = temp

        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    #Produce the final hash value (big-endian) as a 160-bit number:

    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)


if __name__ == "__main__":
    
    t = int(input())
    
    for _ in range(t):
        inp = input()
        hash = sha1(inp) 
        print(hash, len(hash), sep="  ")
