# Embedded file name: encode.py
import cv2


def message_to_bit_generator(message):
    for character in message:
        order = ord(character)
        for i in range(8):
            yield (order & 1 << i) >> i


def restor_message(file_name):
    message = ''
    img = cv2.imread(file_name, cv2.IMREAD_COLOR)
    i = 0
    bits = ''
    for height in range(len(img)):
        for width in range(len(img[0])):
            try:
                bits = str(img[height][width][0] & 0x01) + bits
                i += 1
                if i != 0 and i % 8 == 0:
                    message += chr(int(bits, 2))
                    bits = ''

            except StopIteration as e:
                pass
    return message


def hide_message(input, file_name, output_img):
    # print(''.join(format(ord(x), 'b') for x in input))
    message = message_to_bit_generator(input)
    img = cv2.imread(file_name, cv2.IMREAD_COLOR)
    arr = []

    for height in range(len(img)):
        for width in range(len(img[0])):
            try:
                x = next(message)
                arr.append(x)
                img[height][width][0] = img[height][width][0] & -2 | x
            except StopIteration as e:
                img[height][width][0] = img[height][width][0] & -2 | 0
    cv2.imwrite(output_img, img)
    print(''.join(str(b) for b in arr))
    print('Done creating result file...')