from bs4 import BeautifulSoup
from flask import Flask
import  requests
import psycopg2


app = Flask(__name__)
app.secret_key = 'replace later'

@app.route('/')
def index():
    print(crawle())
    connect()
    return '<h1>successfully</h1>'

def spacee(sp):
    return  sp.strip()

def dele(de):
  return de.replace('-','')


def crawle ():
    html = requests.get("https://tuyensinh.ctu.edu.vn/chuong-trinh-dai-tra/841-danh-muc-nganh-va-chi-tieu-tuyen-sinh-dhcq.html").text
    soup = BeautifulSoup(html, "lxml")

    new_feed = soup.find('section', class_='article-content clearfix').find_all('a')
    ND = soup.find('section', class_='article-content clearfix').find('p')
    divs_TieuDe = soup("html", "com_content view-article itemid-285 j36 mm-hover")
    divs_DL = soup("p", "MsoNormal")

    DL = soup.find('section', class_='article-content clearfix').find_all('p')

    TieuDe = divs_TieuDe[0].find("title").text
    TieuDe1 = divs_TieuDe[0].find("h4").text
    DuLieu = divs_DL[7].text
    # Công nghệ kỹ thuật hóa học
    Ma_CN = divs_DL[6].text
    Ten_CN = divs_DL[7].text
    ToHop_CN = divs_DL[8].text
    ChiTieu_CN = divs_DL[9].text
    TT19_CN = divs_DL[10].text
    TT18_CN = divs_DL[11].text
    TT17_CN = divs_DL[12].text

    # Kỹ thuật cơ điện tử
    Ma_CN1 = divs_DL[13].text
    Ten_CN1 = divs_DL[14].text
    ToHop_CN1 = divs_DL[15].text
    ChiTieu_CN1 = divs_DL[16].text
    TT19_CN1 = divs_DL[17].text
    TT18_CN1 = divs_DL[18].text
    TT17_CN1 = divs_DL[19].text

    # Kỹ thuật cơ khí
    Ma_CN2 = divs_DL[20].text
    Ten_CN2 = divs_DL[21].text
    TenCn_CN2 = divs_DL[22].text
    TenCn1_CN2 = divs_DL[23].text
    ToHop_CN2 = divs_DL[24].text
    ChiTieu_CN2 = divs_DL[25].text
    TT19_CN2 = divs_DL[26].text
    TT18_CN2 = divs_DL[27].text
    TT17_CN2 = divs_DL[28].text

    # ky thuat dien
    Ma_CN3 = divs_DL[29].text
    Ten_CN3 = divs_DL[30].text
    ToHop_CN3 = divs_DL[31].text
    ChiTieu_CN3 = divs_DL[32].text
    TT19_CN3 = divs_DL[33].text
    TT18_CN3 = divs_DL[34].text
    TT17_CN3 = divs_DL[35].text

    # ky thuat dien tu - vien thong
    Ma_CN4 = divs_DL[36].text
    Ten_CN4 = divs_DL[37].text
    ToHop_CN4 = divs_DL[38].text
    ChiTieu_CN4 = divs_DL[39].text
    TT19_CN4 = divs_DL[40].text
    TT18_CN4 = divs_DL[41].text
    TT17_CN4 = divs_DL[42].text
    #Kỹ thuật điều khiển và tự động hóa
    Ma_CN5 = divs_DL[43].text
    Ten_CN5 = divs_DL[44].text
    ToHop_CN5 = divs_DL[45].text
    ChiTieu_CN5 = divs_DL[46].text
    TT19_CN5 = divs_DL[47].text
    TT18_CN5 = divs_DL[48].text
    TT17_CN5 = divs_DL[49].text
    # Kỹ thuật máy tính
    Ma_CN6 = divs_DL[50].text
    Ten_CN6 = divs_DL[51].text
    ToHop_CN6 = divs_DL[52].text
    ChiTieu_CN6 = divs_DL[53].text
    TT19_CN6 = divs_DL[54].text
    TT18_CN6 = divs_DL[55].text
    TT17_CN6 = divs_DL[56].text
    # Kỹ thuật xây dựng
    Ma_CN7 = divs_DL[57].text
    Ten_CN7 = divs_DL[58].text
    ToHop_CN7 = divs_DL[59].text
    ChiTieu_CN7 = divs_DL[60].text
    TT19_CN7 = divs_DL[61].text
    TT18_CN7 = divs_DL[62].text
    TT17_CN7 = divs_DL[63].text
    # Kỹ thuật vật liệu
    Ma_CN8 = divs_DL[64].text
    Ten_CN8 = divs_DL[65].text
    ToHop_CN8 = divs_DL[66].text
    ChiTieu_CN8 = divs_DL[67].text
    TT19_CN8 = divs_DL[68].text
    TT18_CN8 = divs_DL[69].text
    TT17_CN8 = divs_DL[70].text
    # Kỹ thuật xây dựng công trình giao thông
    Ma_CN9 = divs_DL[71].text
    Ten_CN9 = divs_DL[72].text
    ToHop_CN9 = divs_DL[73].text
    ChiTieu_CN9 = divs_DL[74].text
    TT19_CN9 = divs_DL[75].text
    TT18_CN9 = divs_DL[76].text
    TT17_CN9 = divs_DL[77].text
    # Kỹ thuật xây dựng công trình thủy
    Ma_CN10 = divs_DL[78].text
    Ten_CN10 = divs_DL[79].text
    ToHop_CN10 = divs_DL[80].text
    ChiTieu_CN10 = divs_DL[81].text
    TT19_CN10 = divs_DL[82].text
    TT18_CN10 = divs_DL[83].text
    TT17_CN10 = divs_DL[84].text
    # Quản lý công nghiệp
    Ma_CN11 = divs_DL[85].text
    Ten_CN11 = divs_DL[86].text
    ToHop_CN11 = divs_DL[87].text
    ChiTieu_CN11 = divs_DL[88].text
    TT19_CN11 = divs_DL[89].text
    TT18_CN11 = divs_DL[90].text
    TT17_CN11 = divs_DL[91].text
    # Công nghệ thông tin
    Ma_CNTT = divs_DL[92].text
    Ten_CNTT = divs_DL[93].text
    TenCn_CNTT = divs_DL[94].text
    TenCn1_CNTT = divs_DL[95].text
    ToHop_CNTT = divs_DL[96].text
    ChiTieu_CNTT = divs_DL[97].text
    TT19_CNTT = divs_DL[98].text
    TT18_CNTT = divs_DL[99].text
    TT17_CNTT = divs_DL[100].text
    # Hệ thống thông tin
    Ma_CNTT1 = divs_DL[101].text
    Ten_CNTT1 = divs_DL[102].text
    ToHop_CNTT1 = divs_DL[103].text
    ChiTieu_CNTT1 = divs_DL[104].text
    TT19_CNTT1 = divs_DL[105].text
    TT18_CNTT1 = divs_DL[106].text
    TT17_CNTT1 = divs_DL[107].text
    # Khoa học máy tính
    Ma_CNTT2 = divs_DL[108].text
    Ten_CNTT2 = divs_DL[109].text
    ToHop_CNTT2 = divs_DL[110].text
    ChiTieu_CNTT2 = divs_DL[111].text
    TT19_CNTT2 = divs_DL[112].text
    TT18_CNTT2 = divs_DL[113].text
    TT17_CNTT2 = divs_DL[114].text
    # Kỹ thuật phần mềm
    Ma_CNTT3 = divs_DL[115].text
    Ten_CNTT3 = divs_DL[116].text
    ToHop_CNTT3 = divs_DL[117].text
    ChiTieu_CNTT3 = divs_DL[118].text
    TT19_CNTT3 = divs_DL[119].text
    TT18_CNTT3 = divs_DL[120].text
    TT17_CNTT3 = divs_DL[121].text
    # Mạng máy tính và truyền thông dữ liệu
    Ma_CNTT4 = divs_DL[122].text
    Ten_CNTT4 = divs_DL[123].text
    ToHop_CNTT4 = divs_DL[124].text
    ChiTieu_CNTT4 = divs_DL[125].text
    TT19_CNTT4 = divs_DL[126].text
    TT18_CNTT4 = divs_DL[127].text
    TT17_CNTT4 = divs_DL[128].text
    # Chính trị học
    Ma_CT = divs_DL[129].text
    Ten_CT = divs_DL[130].text
    ToHop_CT = divs_DL[131].text
    ChiTieu_CT = divs_DL[132].text
    TT19_CT = divs_DL[133].text
    TT18_CT = divs_DL[134].text
    TT17_CT = divs_DL[135].text
    # Triết học
    Ma_CT1 = divs_DL[136].text
    Ten_CT1 = divs_DL[137].text
    ToHop_CT1 = divs_DL[138].text
    ChiTieu_CT1 = divs_DL[139].text
    TT19_CT1 = divs_DL[140].text
    TT18_CT1 = divs_DL[141].text
    TT17_CT1 = divs_DL[142].text
    # Công nghệ sinh học
    Ma_KHTN = divs_DL[143].text
    Ten_KHTN = divs_DL[144].text
    ToHop_KHTN = divs_DL[145].text
    ChiTieu_KHTN = divs_DL[146].text
    TT19_KHTN = divs_DL[147].text
    TT18_KHTN = divs_DL[148].text
    TT17_KHTN = divs_DL[149].text
    # Hóa dược
    Ma_KHTN1 = divs_DL[150].text
    Ten_KHTN1 = divs_DL[151].text
    ToHop_KHTN1 = divs_DL[152].text
    ChiTieu_KHTN1 = divs_DL[153].text
    TT19_KHTN1 = divs_DL[154].text
    TT18_KHTN1 = divs_DL[155].text
    TT17_KHTN1 = divs_DL[156].text
    # Hóa học
    Ma_KHTN2 = divs_DL[157].text
    Ten_KHTN2 = divs_DL[158].text
    ToHop_KHTN2 = divs_DL[159].text
    ChiTieu_KHTN2 = divs_DL[160].text
    TT19_KHTN2 = divs_DL[161].text
    TT18_KHTN2 = divs_DL[162].text
    TT17_KHTN2 = divs_DL[163].text
    # Sinh học
    Ma_KHTN3 = divs_DL[164].text
    Ten_KHTN3 = divs_DL[165].text
    ToHop_KHTN3 = divs_DL[166].text
    ChiTieu_KHTN3 = divs_DL[167].text
    TT19_KHTN3 = divs_DL[168].text
    TT18_KHTN3 = divs_DL[169].text
    TT17_KHTN3 = divs_DL[170].text
    # Toán ứng dụng
    Ma_KHTN4 = divs_DL[171].text
    Ten_KHTN4 = divs_DL[172].text
    ToHop_KHTN4 = divs_DL[173].text
    ChiTieu_KHTN4 = divs_DL[174].text
    TT19_KHTN4 = divs_DL[175].text
    TT18_KHTN4 = divs_DL[176].text
    TT17_KHTN4 = divs_DL[177].text
    # Vật lý kỹ thuật
    Ma_KHTN5 = divs_DL[178].text
    Ten_KHTN5 = divs_DL[179].text
    ToHop_KHTN5 = divs_DL[180].text
    ChiTieu_KHTN5 = divs_DL[181].text
    TT19_KHTN5 = divs_DL[182].text
    TT18_KHTN5 = divs_DL[183].text
    TT17_KHTN5 = divs_DL[184].text

    return spacee(dele(Ma_KHTN5)),spacee(dele(Ten_KHTN5)),spacee(dele(ToHop_KHTN5)),spacee(dele(ChiTieu_KHTN5)), spacee(dele(TT19_KHTN5))\
          ,spacee(dele(TT18_KHTN5)),spacee(dele(TT17_KHTN5))

def connect() :
    try:
        connection = psycopg2.connect(user="halepmhfxnkrni",
                                      password="48e8d7e4ed72113de1dad744a6a3be7380d7602df430187473ed6decae2d2d6f",
                                      host="ec2-35-169-254-43.compute-1.amazonaws.com",
                                      port="5432",
                                      database="daerabpc01h014")

        cursor = connection.cursor()
        # Print PostgreSQL Connection properties
        print(connection.get_dsn_parameters(), "\n")


        # Print PostgreSQL version
        cursor.execute("SELECT version();")
        record = cursor.fetchone()
        print("You are connected to - ", record, "\n")

        create_table_query = '''CREATE TABLE dmnganh(
                 Manganh          TEXT PRIMARY KEY NOT NULL,
                 Tennganh         TEXT NOT NULL,
                 Tohop            TEXT NOT NULL,
                 Chitieu          TEXT NOT NULL,
                 TT2019           TEXT NOT NULL,
                 TT2018           TEXT NOT NULL,
                 TT2017           TEXT NOT NULL); '''

        #cursor.execute(create_table_query)
        #print("creeate success")
        #cursor.execute("DROP TABLE dmnganh;")
        #print("delete successfully")

        cursor.execute("INSERT INTO dmnganh (Manganh,Tennganh,Tohop,Chitieu,TT2019,TT2018,TT2017) VALUES(%s, %s, %s, %s, %s, %s, %s)", (crawle()))
        print("insert successfully")

        cursor.execute("SELECT * FROM dmnganh;")
        records = cursor.fetchall()
        print(records)


        #cursor.execute("SELECT Tennganh FROM dmnganh;")
        #re = cursor.fetchall()
        #print(re[1])

        connection.commit()
        #print("Table created successfully in PostgreSQL ")


    except (Exception, psycopg2.Error) as error:
        print("Error while connecting to PostgreSQL", error)
    finally:
        # closing database connection.
        if (connection):

            cursor.close()
            connection.close()
            print("PostgreSQL connection is closed")


if __name__ == '__main__' :

    app.run(debug=True)
    # pip freeze > requirements.txt