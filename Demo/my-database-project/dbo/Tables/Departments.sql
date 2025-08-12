CREATE TABLE [dbo].[Departments] (
    [DepartmentID] INT            IDENTITY (1, 1) NOT NULL,
    [Name]         NVARCHAR (100) NULL,
    [Floor]        INT            NULL,
    [Phone]        NVARCHAR (20)  NULL,
    PRIMARY KEY CLUSTERED ([DepartmentID] ASC)
);
GO

