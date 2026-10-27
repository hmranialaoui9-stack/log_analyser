from ingestion import raw


from process import extract_transforme

if __name__ == '__main__' :
    extract_transforme.extract_from_row(raw.toRows('./data')[0])