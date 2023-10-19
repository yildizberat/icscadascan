import pandas as pd

df = pd.read_csv('./icsprotoport2.csv',sep=';')
pd.set_option('display.max_rows', df.shape[0]+1)
print(df)