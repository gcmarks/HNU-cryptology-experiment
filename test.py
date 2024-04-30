import csv

data = [
    ['John', 'Doe', 30]
]

filename = 'data.csv'

with open(filename, 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerows(data)