# SQLServer Lab 04 - Ma hoa RSA o client

Do an nay bam theo file `docs/BMCSDL - Lab04.pdf`:

- Client C# tu hash mat khau bang SHA1 truoc khi gui SQL Server.
- Client C# tu sinh cap khoa RSA 2048 cho tung nhan vien.
- Client C# tu ma hoa `LUONG` va `DIEMTHI` bang public key cua nhan vien.
- `LUONG` con duoc ma hoa lan hai bang public key cua ADMIN va luu vao cot `LUONG_ADMIN`, nho do admin dung private key cua minh giai ma duoc luong cua MOI nhan vien. Mat khau (`MATKHAU`) van la SHA1 mot chieu nen khong ai (ke ca admin) xem nguoc ra duoc.
- Co role `ADMIN`/`NHANVIEN`; chi admin duoc nhap/thay doi luong, them hoc phan, tao lop.
- Admin co the quan ly toan bo lop/sinh vien/diem; nhan vien thuong chi thao tac tren lop minh phu trach.
- Man hinh `Register` tao account nhan vien thuong, chua co luong.
- SQL Server chi luu ciphertext va tra ciphertext, khong goi `EncryptByAsymKey` hay `DecryptByAsymKey`.
- Client C# cache mat khau/private key trong phien dang nhap de giai ma khi xem luong/diem.

## Cau truc file

| File | Noi dung |
| --- | --- |
| `01_schema.sql` | Tao database `QLSVNhom` va cac bang |
| `02_procedures.sql` | Tao stored procedures cho Lab4 |
| `03_sample_base.sql` | Nap hoc phan mau; du lieu nhan vien/sinh vien duoc seed bang app C# |
| `Program.cs` | Ung dung WinForms: dang nhap, nhan vien, lop, sinh vien, bang diem |
| `SQLServerLab4.csproj` | Project .NET WinForms |

## Cach chay SQL

Mo SSMS va chay lan luot:

```sql
01_schema.sql
02_procedures.sql
03_sample_base.sql
```

Database mac dinh la `QLSVNhom`.

## Cach chay app

Can .NET SDK va SQL Server local. Trong thu muc nay:

```powershell
dotnet restore
dotnet run
```

O man hinh dang nhap:

1. Kiem tra `Server` va `Database`.
2. Bam `Seed mau` neu moi tao database.
3. Dang nhap bang:

| MANV | Mat khau | Lop quan ly |
| --- | --- | --- |
| `ADMIN` | `admin123` | quan tri |
| `NV01` | `abcd12` | `L01` |
| `NV02` | `pass02` | `L02` |
| `NV03` | `pass03` | chua quan ly lop |

Private key duoc luu tai `bin/Debug/net10.0-windows/keys/*.private.bin`, ma hoa bang mat khau cua nhan vien.

Nut `Register` tao tai khoan role `NHANVIEN`. Tai khoan moi co public/private key rieng; admin se cap nhat luong sau trong tab `Nhan vien`.

## Stored procedure chinh theo de

Them nhan vien:

```sql
EXEC SP_INS_PUBLIC_ENCRYPT_NHANVIEN
    @MANV, @HOTEN, @EMAIL, @LUONG, @LUONG_ADMIN, @TENDN, @MK, @PUB, @VAITRO, @MANV_LOGIN;
```

Trong do `@LUONG` la ciphertext ma hoa bang public key cua chinh nhan vien, `@LUONG_ADMIN` la ciphertext ma hoa bang public key cua admin (lay qua `SP_SEL_ADMIN_PUBLICKEY`), `@MK` la SHA1 hash tu client, `@PUB` la public key RSA 2048 tu client. Sau khi da co du lieu nhan vien, `@MANV_LOGIN` phai la admin.

Register nhan vien thuong:

```sql
EXEC SP_REGISTER_NHANVIEN @MANV, @HOTEN, @EMAIL, @TENDN, @MK, @PUB;
```

Cap nhat luong:

```sql
EXEC SP_UPD_NHANVIEN_LUONG @MANV, @LUONG, @LUONG_ADMIN, @MANV_LOGIN;
```

App ma hoa luong hai lan: `@LUONG` bang public key cua `@MANV`, `@LUONG_ADMIN` bang public key admin, roi moi goi procedure. SQL Server chan neu `@MANV_LOGIN` khong phai admin.

Cac procedure ho tro / moi them:

```sql
EXEC SP_SEL_ADMIN_PUBLICKEY;            -- lay public key admin de ma hoa LUONG_ADMIN
EXEC SP_SEL_SV_ALL @MANV_LOGIN;         -- admin xem toan bo SV, NV thuong chi xem SV lop minh phu trach
EXEC SP_INS_HOCPHAN @MAHP, @TENHP, @SOTC, @MANV_LOGIN;   -- chi admin (khi DB da co nhan vien)
EXEC SP_INS_LOP @MALOP, @TENLOP, @MANV, @MAHP, @MANV_LOGIN; -- chi admin tao lop
EXEC SP_DEL_SV @MASV, ..., @MANV_LOGIN; -- xoa SV kem theo BANGDIEM va go tham chieu LOP.MASV (cascade)
```

Truy van nhan vien:

```sql
EXEC SP_SEL_PUBLIC_ENCRYPT_NHANVIEN @TENDN, @MK;
```

Ket qua tra ve `LUONG` van la ciphertext. App C# moi giai ma o client.

## Goi y SQL Profiler

Khi nhap diem trong app, Profiler se thay stored procedure:

```sql
exec SP_INS_BANGDIEM_ENCRYPT @MASV=..., @MAHP=..., @DIEMTHI=0x..., @MANV_LOGIN=...
```

Nhan xet: gia tri diem khong xuat hien dang plaintext trong Profiler; SQL Server chi nhan chuoi bytes `0x...`. Dieu nay dung yeu cau Lab4 vi ma hoa da dien ra truoc khi gui xuong CSDL.
