import cv2
import os

ROOT = '/home/shashank/PycharmProjects/pythonProject/security/resources/pcaps/detector/pictures'
FACES = '/home/shashank/PycharmProjects/pythonProject/security/resources/pcaps/detector/faces'
TRAIN = '/home/shashank/PycharmProjects/pythonProject/security/resources/pcaps/detector/training/new'


def detect(srcdir=ROOT, trgdir=FACES, trndir=TRAIN):
    for file_name in os.listdir(srcdir):
        if not (file_name.lower().endswith('.jpg') or file_name.lower().endswith('.jpeg')):
            continue
        full_name = os.path.join(srcdir, file_name)
        new_name = os.path.join(trgdir, file_name)
        img = cv2.imread(full_name)
        if img is None:
            continue

        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        training = os.path.join(trndir, 'haarcascade_frontalface_alt.xml')
        cascade = cv2.CascadeClassifier(training)
        rects = cascade.detectMultiScale(gray, 1.3, 5)
        try:
            if rects.any():
                print("Got A Face")
                rects[:, 2:] += rects[:, :2]
                for x1, y1, x2, y2 in rects:
                    cv2.rectangle(img, (x1, y1), (x2, y2), (127, 255, 0), 2)
                cv2.imwrite(new_name, img)
            else:
                print(f'no face found in this image {file_name}')
        except AttributeError:
            print(f'no face found in this image {file_name}')


if __name__ == "__main__":
    detect()
