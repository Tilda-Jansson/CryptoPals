from utils.ch9 import unpad

def main():
    try:
        test_valid = unpad(b"ICE ICE BABY\x04\x04\x04\x04", 16)
    except ValueError as err:
        print(err)
    else:
        print("Valid as expected")
    
    try:
        test_invalid1 = unpad(b"ICE ICE BABY\x05\x05\x05\x05", 16)
    except ValueError as err:
        print(err)
    else:
        print("Expected a padding error")
    
    try:
        test_invalid2 = unpad(b"ICE ICE BABY\x01\x02\x03\x04", 16)
    except ValueError as err:
        print(err)
    else:
        print("Expected a padding error")
    
if __name__ == '__main__':
    main()