CREATE TABLE [dbo].[LabTests] (
    [LabTestID]   INT             IDENTITY (1, 1) NOT NULL,
    [Name]        NVARCHAR (100)  NULL,
    [Description] NVARCHAR (250)  NULL,
    [Cost]        DECIMAL (10, 2) NULL,
    PRIMARY KEY CLUSTERED ([LabTestID] ASC)
);
GO

