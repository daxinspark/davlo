CREATE TABLE [dbo].[Treatments] (
    [TreatmentID] INT             IDENTITY (1, 1) NOT NULL,
    [Name]        NVARCHAR (100)  NULL,
    [Description] NVARCHAR (500)  NULL,
    [Cost]        DECIMAL (10, 2) NULL,
    PRIMARY KEY CLUSTERED ([TreatmentID] ASC)
);
GO

