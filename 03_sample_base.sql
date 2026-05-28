/* =========================================================
   SQLServer Lab 04 - Base sample data
   Employee/student/password/salary/score data must be inserted
   by the C# client because Lab04 requires client-side crypto.
   ========================================================= */
USE QLSVNhom;
GO

EXEC SP_INS_HOCPHAN 'CSDL',  N'Co so du lieu', 4;
EXEC SP_INS_HOCPHAN 'ATBM',  N'An toan bao mat thong tin', 3;
EXEC SP_INS_HOCPHAN 'LTHDT', N'Lap trinh huong doi tuong', 4;
GO

PRINT N'Inserted base courses. Use the Seed button in the C# app to create encrypted sample employees, classes, students and scores.';
GO
