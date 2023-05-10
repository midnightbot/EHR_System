import math
import copy

s_box = [
    [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
    [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
    [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
    [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
    [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
    [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
    [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
    [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
    [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
    [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
    [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
    [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
    [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
    [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
    [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
    [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
]

c = [
    [2,3,1,1],
    [1,2,3,1],
    [1,1,2,3],
    [3,1,1,2]
]

r_con = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

def get_s_box_row_col(str):
    '''
    Given a string, it finds the row,col position of the element to be used for s_box subsitution
    '''
    if type(str) == type('a'):
        hex_int = int(str, 16)
    else:
        hex_int = str
    row = hex_int//16
    col = hex_int%16

    return row,col

def sub_bytes(msg):
    '''
    Given an input msg, it substitutes each element of the array with appropriate s_box element
    '''
    ans = [[0 for x in range(len(msg[0]))] for y in range(len(msg))]

    for x in range(len(msg)):
        for y in range(len(msg[0])):
            r,c = get_s_box_row_col(msg[x][y])
            ans[x][y] = hex(s_box[r][c])

    return ans

def shift_row(msg):
    '''
    Performs shift row operation
    '''
    ans = []
    ans.append(msg[0])
    ans.append([msg[1][1], msg[1][2], msg[1][3], msg[1][0]])
    ans.append([msg[2][2], msg[2][3], msg[2][0], msg[2][1]])
    ans.append([msg[3][3], msg[3][0], msg[3][1], msg[3][2]])
    return ans

def find_value(val, c):
    '''
    Helper function for mix column operation
    Helps find val * c 
    '''
    if type(val) == type('a'):
        val = int(val, 16)

    if c == 1:
        str_val = format(val, 'b')
        str_val = str_val[::-1]

        arr = [0 for x in range(9)]
        for x in range(len(str_val)):
            if str_val[x] == '1':
                arr[x] = 1
            else:
                arr[x] = 0

        arr = arr[::-1]
        return arr

    elif c==2:
        str_val = format(val, 'b')

        str_val = str_val[::-1]

        arr = [0 for x in range(9)]
        for x in range(len(str_val)):
            if str_val[x] == '1':
                arr[x] = 1
            else:
                arr[x] = 0

        new_arr = [0 for x in range(9)]
        for x in range(len(arr)):
            if arr[x] == 1:
                new_arr[x+1] = 1

        new_arr = new_arr[::-1]
        return new_arr

    elif c==3:
        str_val = format(val, 'b')
        str_val = str_val[::-1]

        arr = [0 for x in range(9)]
        for x in range(len(str_val)):
            if str_val[x] == '1':
                arr[x] = 1
            else:
                arr[x] = 0

        new_arr = [0 for x in range(9)]
        for x in range(len(arr)):
            if arr[x] == 1:
                new_arr[x+1] = 1

        final_ans = [arr[x] + new_arr[x] for x in range(len(arr))]
        final_ans = [x%2 for x in final_ans]
        final_ans = final_ans[::-1]
        return final_ans


def find_row_col_mix_value(col, row):
    '''
    Helper function for mix column operation
    '''
    a = find_value(col[0], row[0])
    b = find_value(col[1], row[1])
    c = find_value(col[2], row[2])
    d = find_value(col[3], row[3])
    a,b,c,d = a[::-1], b[::-1], c[::-1], d[::-1]
    ans = [0 for x in range(len(max(a,b,c,d)))]
    for x in range(len(a)):
        ans[x] = a[x] + b[x] + c[x] + d[x]

    ans = [x%2 for x in ans]
    if ans[8] == 1:
        ans[8]+=1
        ans[4]+=1
        ans[3]+=1
        ans[1]+=1
        ans[0]+=1
        ans = [x%2 for x in ans]
    ans = ans[::-1]
    ans = [str(x) for x in ans]
    ans = "".join(ans)
    ans = int(ans, 2)
    return hex(ans)


def mix_cols(msg):
    '''
    Performs Mix column operation
    '''
    col0 = [msg[0][0], msg[1][0], msg[2][0], msg[3][0]]
    col1 = [msg[0][1], msg[1][1], msg[2][1], msg[3][1]]
    col2 = [msg[0][2], msg[1][2], msg[2][2], msg[3][2]]
    col3 = [msg[0][3], msg[1][3], msg[2][3], msg[3][3]]

    ans_row1 = [find_row_col_mix_value(col0, c[0]), find_row_col_mix_value(col0, c[1]), find_row_col_mix_value(col0, c[2]), find_row_col_mix_value(col0, c[3])]
    ans_row2 = [find_row_col_mix_value(col1, c[0]), find_row_col_mix_value(col1, c[1]), find_row_col_mix_value(col1, c[2]), find_row_col_mix_value(col1, c[3])]
    ans_row3 = [find_row_col_mix_value(col2, c[0]), find_row_col_mix_value(col2, c[1]), find_row_col_mix_value(col2, c[2]), find_row_col_mix_value(col2, c[3])]
    ans_row4 = [find_row_col_mix_value(col3, c[0]), find_row_col_mix_value(col3, c[1]), find_row_col_mix_value(col3, c[2]), find_row_col_mix_value(col3, c[3])]

    return [ans_row1, ans_row2, ans_row3, ans_row4]

def add_initial_round_key(arr1, arr2):
    '''
    Returns an XOR of two arrays
    '''
    arr1_rot = arr1
    for x in range(len(arr1_rot)):
        for y in range(len(arr1_rot[0])):
            if type(arr1_rot[x][y]) == type('a'):
                arr1_rot[x][y] = int(arr1_rot[x][y], 16)
    for x in range(len(arr2)):
        for y in range(len(arr2[0])):
            if type(arr2[x][y]) == type('a'):
                arr2[x][y] = int(arr2[x][y], 16)

    ans = [[0 for x in range(len(arr1[0]))] for y in range(len(arr1))]

    for x in range(len(arr1)):
        for y in range(len(arr1[0])):
            ans[x][y] = hex(arr1_rot[x][y] ^ arr2[x][y])

    return ans

def add_round_key(arr1, arr2):
    '''
    Returns an XOR of two arrays
    '''
    ##arr1.transpose as mixcolumn is performed before add key
    arr1_copy = copy.deepcopy(arr1)
    arr1_rot = []
    arr1_rot.append([arr1_copy[0][0], arr1_copy[1][0], arr1_copy[2][0], arr1_copy[3][0]])
    arr1_rot.append([arr1_copy[0][1], arr1_copy[1][1], arr1_copy[2][1], arr1_copy[3][1]])
    arr1_rot.append([arr1_copy[0][2], arr1_copy[1][2], arr1_copy[2][2], arr1_copy[3][2]])
    arr1_rot.append([arr1_copy[0][3], arr1_copy[1][3], arr1_copy[2][3], arr1_copy[3][3]])

    for x in range(len(arr1_rot)):
        for y in range(len(arr1_rot[0])):
            if type(arr1_rot[x][y]) == type('a'):
                arr1_rot[x][y] = int(arr1_rot[x][y], 16)
    for x in range(len(arr2)):
        for y in range(len(arr2[0])):
            if type(arr2[x][y]) == type('a'):
                arr2[x][y] = int(arr2[x][y], 16)

    ans = [[0 for x in range(len(arr1[0]))] for y in range(len(arr1))]

    for x in range(len(arr1)):
        for y in range(len(arr1[0])):
            ans[x][y] = hex(arr1_rot[x][y] ^ arr2[x][y])

    return ans

def g_function(cols, round):
    '''
    Implements the g function
    '''
    col = copy.deepcopy(cols)
    ## rotate
    col = col[1:] + [col[0]]
    ##s-box
    for x in range(len(col)):
        r,c = get_s_box_row_col(col[x])
        col[x] = hex(s_box[r][c])

    ## converting string to int
    for x in range(len(col)):
        if type(col[x]) == type('a'):
            col[x] = int(col[x], 16)

    ##xor
    col[0] = hex(col[0] ^ r_con[round-1])
    return col


def aes_key_expansion(key, round):
    '''
    Produces key for a particular round
    '''
    col0 = [key[0][0], key[1][0], key[2][0], key[3][0]]
    col1 = [key[0][1], key[1][1], key[2][1], key[3][1]]
    col2 = [key[0][2], key[1][2], key[2][2], key[3][2]]
    col3 = [key[0][3], key[1][3], key[2][3], key[3][3]]

    g = g_function(col3, round)
    for x in range(len(g)):
        if type(g[x]) == type('a'):
            g[x] = int(g[x], 16)

    new_col0 = []
    for x in range(len(col0)):
        new_col0.append(hex(col0[x] ^ g[x]))
    ## w4 = w0 XOR g(w3)
    ## w5 = w4 XOR w1
    ## w6 = w5 XOR w2
    ## w7 = w6 XOR w3
    for x in range(len(new_col0)):
        if type(new_col0[x]) == type('a'):
            new_col0[x] = int(new_col0[x], 16)

    new_col1 = []
    for x in range(len(col1)):
        new_col1.append(hex(col1[x] ^ new_col0[x]))

    new_col2 = []
    for x in range(len(new_col1)):
        if type(new_col1[x]) == type('a'):
            new_col1[x] = int(new_col1[x], 16)

    for x in range(len(col2)):
        new_col2.append(hex(col2[x] ^ new_col1[x]))

    new_col3 = []
    for x in range(len(new_col2)):
        if type(new_col2[x]) == type('a'):
            new_col2[x] = int(new_col2[x], 16)

    for x in range(len(new_col2)):
        new_col3.append(hex(col3[x] ^ new_col2[x]))

    for x in range(len(new_col3)):
        if type(new_col3[x]) == type('a'):
            new_col3[x] = int(new_col3[x], 16)

    new_col0 = [hex(x) for x in new_col0]
    new_col1 = [hex(x) for x in new_col1]
    new_col2 = [hex(x) for x in new_col2]
    new_col3 = [hex(x) for x in new_col3]
    new_key = []

    new_key.append([new_col0[0], new_col1[0], new_col2[0], new_col3[0]])
    new_key.append([new_col0[1], new_col1[1], new_col2[1], new_col3[1]])
    new_key.append([new_col0[2], new_col1[2], new_col2[2], new_col3[2]])
    new_key.append([new_col0[3], new_col1[3], new_col2[3], new_col3[3]])

    return new_key
    

## convert text message to hex input
def convert_to_hex(message):
    '''
    Converts text to hex array representation
    '''
    ## PKCS7 padding scheme
    if len(message) != 16:
        lens = len(message)
        pad_length = 16 - lens
        message = message + "".join([chr(pad_length) for x in range(pad_length)])

    msg_rep = []
    msg_rep.append([hex(ord(message[0])),hex(ord(message[4])), hex(ord(message[8])), hex(ord(message[12]))])
    msg_rep.append([hex(ord(message[1])), hex(ord(message[5])), hex(ord(message[9])), hex(ord(message[13]))])
    msg_rep.append([hex(ord(message[2])), hex(ord(message[6])), hex(ord(message[10])), hex(ord(message[14]))])
    msg_rep.append([hex(ord(message[3])), hex(ord(message[7])), hex(ord(message[11])), hex(ord(message[15]))])

    return msg_rep

def create_cipher_key_rep(c_key):
    '''
    Creates the cipher key array from the cipher key string
    '''
    cipherkey = []
    if " " not in c_key:
        hexs = []
        for x in range(0, len(c_key), 2):
            hexs.append(c_key[x:x+2])
    else:
        hexs = c_key.split(" ")
    cipherkey.append([hex(int(hexs[0],16)), hex(int(hexs[4],16)), hex(int(hexs[8],16)), hex(int(hexs[12],16))])
    cipherkey.append([hex(int(hexs[1],16)), hex(int(hexs[5],16)), hex(int(hexs[9],16)), hex(int(hexs[13],16))])
    cipherkey.append([hex(int(hexs[2],16)), hex(int(hexs[6],16)), hex(int(hexs[10],16)), hex(int(hexs[14],16))])
    cipherkey.append([hex(int(hexs[3],16)), hex(int(hexs[7],16)), hex(int(hexs[11],16)), hex(int(hexs[15],16))])

    return cipherkey

def convert_hex_to_msg(arr):
    '''
    Converts the hex array back to string text
    '''
    result = ""
    for x in range(len(arr)):
        for y in range(len(arr[0])):
            curr = arr[y][x][2:]
            if len(curr) == 1:
                curr = '0' + curr
            result+=curr
    
    
    return result

def main(msgs, ckey):
    '''
    Entrypoint of the aesencrypt
    '''
    final_result = ""
    
    if len(msgs)%16==0:
        msgs+= "".join([chr(16) for x in range(16)])

    number_of_messages = math.ceil(len(msgs)/16)
    
    for it in range(number_of_messages):
        msg = msgs[16*it:16*(it+1)]
        msg = convert_to_hex(msg)
        cipher_key = create_cipher_key_rep(ckey)
        a = add_initial_round_key(msg, cipher_key)
        

        for x in range(10):
            if x < 9:
                sub1 = sub_bytes(a)
                shift1 = shift_row(sub1)
                mixing = mix_cols(shift1)
                cipher_key = aes_key_expansion(cipher_key, x+1)
                add_round_key1 = add_round_key(mixing, cipher_key)
                a = add_round_key1

            else:
                sub1 = sub_bytes(a)
                shift1 = shift_row(sub1)
                cipher_key = aes_key_expansion(cipher_key, x+1)
                add_round_key1 = add_initial_round_key(shift1, cipher_key)


        final_result+= convert_hex_to_msg(add_round_key1)

    return final_result

if __name__ == "__main__":
    print("Using PKCS7 padding")
    print("Input your message to be encrypted (Plaintext)(Eg : anish adnani)")
    msgs = input()
    print("Input your key to be used for encryption(Hex)(Eg:31323334353637383930313233343536)")
    ckey = input()

    encrypted_msg = main(msgs, ckey)
    print("Encrypted message is : ")
    print(encrypted_msg)