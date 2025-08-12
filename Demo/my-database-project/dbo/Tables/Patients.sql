CREATE TABLE [dbo].[Patients] (
    [PatientID]        INT            IDENTITY (1, 1) NOT NULL,
    [FirstName]        NVARCHAR (50)  NULL,
    [LastName]         NVARCHAR (50)  NULL,
    [DateOfBirth]      DATE           NULL,
    [Gender]           CHAR (1)       NULL,
    [Phone]            NVARCHAR (20)  NULL,
    [Email]            NVARCHAR (100) NULL,
    [Address]          NVARCHAR (200) NULL,
    [City]             NVARCHAR (50)  NULL,
    [State]            NVARCHAR (50)  NULL,
    [ZipCode]          NVARCHAR (10)  NULL,
    [RegistrationDate] DATE           NULL,
    PRIMARY KEY CLUSTERED ([PatientID] ASC)
);
GO

