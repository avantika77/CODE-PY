import pandas as pd
data = {
    'ID': [1, 2, 3, 4],
    'Name': ['Alice', 'Bob', 'Charlie', 'David'],
    'Age': [25, 30, 35, 40]
}
df = pd.DataFrame(data)
print("Original:\n", df)
# Selecting Columns from the DataFrame
age_series = df['Age']  # Selecting single column
print("\nAge Column:\n", age_series)
df_subset = df[['Name', 'Age']]  # Selecting multiple columns
print("\nSelected Columns (Name, Age):\n", df_subset)

# Selecting Rows from the DataFrame
row = df.iloc[1]  # Selecting second row
print("\nSecond Row:\n", row)

df_filtered = df[df['Age'] > 30]  # Selecting rows where Age > 30
print("\nRows where Age > 30:\n", df_filtered)

# Adding New Data
df['Salary'] = [50000, 60000, 70000, 80000]  # Adding new column
print("\n DataFrame After Adding Salary Column:\n", df)

df.loc[4] = [5, 'Eve', 28, 55000]  # Adding a new row
print("\n DataFrame After Adding a New Row:\n", df)

# Deleting Data
df.drop(columns=['Salary'], inplace=True)  # Deleting the Salary column
print("\nDataFrame After Deleting Salary Column:\n", df)

df.drop(index=2, inplace=True)  # Deleting row with index 2
print("\nDataFrame After Deleting Row with Index 2:\n", df)

df = df[df['Age'] < 35]  # Removing rows where Age >= 35
print("\nDataFrame After Removing Rows Where Age >= 35:\n", df)

