CREATE TABLE [dbo].[Nurses] (
    [NurseID]   INT            IDENTITY (1, 1) NOT NULL,
    [FirstName] NVARCHAR (50)  NULL,
    [LastName]  NVARCHAR (50)  NULL,
    [Phone]     NVARCHAR (20)  NULL,
    [Email]     NVARCHAR (100) NULL,
    [HireDate]  DATE           NULL,
    PRIMARY KEY CLUSTERED ([NurseID] ASC)
);
GO

