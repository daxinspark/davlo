CREATE TABLE [dbo].[Medications] (
    [MedicationID] INT             IDENTITY (1, 1) NOT NULL,
    [Name]         NVARCHAR (100)  NULL,
    [Description]  NVARCHAR (250)  NULL,
    [Manufacturer] NVARCHAR (100)  NULL,
    [Price]        DECIMAL (10, 2) NULL,
    PRIMARY KEY CLUSTERED ([MedicationID] ASC)
);
GO

