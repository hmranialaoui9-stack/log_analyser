import gzip
import os
"""
raed data logs from data directory as rows 
"""


def toRows(path):
    files=os.listdir(path)

    for file in files :
        file_path=path+'/'+file
        openner=gzip.open(filename=file_path,mode='rt',encoding='utf-8') if file.endswith('.gz') else open(file_path)
        with openner as f :
            rows=f.readlines()
    return rows

if __name__=='__main__':
    print(toRows('./data')[:10])