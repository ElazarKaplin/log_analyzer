import csv


def load_log_data(file_path):
    data = []
    try:
        with open(file_path, mode='r', encoding='utf-8') as file:
            csv_reader = csv.reader(file)
            for row in csv_reader:
                if row:
                    data.append(row)
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")

    return data




def stream_log_data(filepath):
    with open(filepath, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            yield row