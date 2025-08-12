CREATE TABLE [dbo].[PatientTreatments] (
    [PatientTreatmentID] INT            IDENTITY (1, 1) NOT NULL,
    [PatientID]          INT            NULL,
    [TreatmentID]        INT            NULL,
    [TreatmentDate]      DATE           NULL,
    [Outcome]            NVARCHAR (250) NULL,
    PRIMARY KEY CLUSTERED ([PatientTreatmentID] ASC),
    FOREIGN KEY ([PatientID]) REFERENCES [dbo].[Patients] ([PatientID]),
    FOREIGN KEY ([TreatmentID]) REFERENCES [dbo].[Treatments] ([TreatmentID])
);
GO

