import pandas as pd
data = [10, 20.06, "hello", 40000.0,-6.09,-7] # Creating a Series 
series = pd.Series(data)
print(series)
print ("Data type", series.dtype)
#data_float=series.astype(float)
#print(data_float)
print()

#custom index
Data2=[200,70,2.9,900]
index_label=['#','b','c','d']
series = pd.Series(Data2, index=index_label)
print(series)
print()

#DataFrame creation
data3={
    'Name':["Alice","Bob","Paul"],
    'Age':[25,45,27],
    'City':["New York","Los Angeles","Chicago"],
    'Salary':[70000,80000,60000],
}
df=pd.DataFrame(data3)
print(df)

print() # line break
Data4=[['Alice',25,"New York",70000],
       ['Bob',45,"Los Angeles",80000],
       ['Paul',27,"Chicago",60000]
       ]
Columns=['Name','Age','City','Salary']
df=pd.DataFrame(Data4,columns=Columns)
print(df)

# data from a CSV file
#df = pd.read_csv('data.csv')  
#print(df.head()) 

df = pd.read_csv(r"C:\Users\AVANTIKA\Desktop\pandas program\student.csv")  # Load data from a CSV file
print(df.head())  # Display first 5 rows



