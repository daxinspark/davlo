CREATE TABLE [dbo].[PatientInsurance] (
    [PatientInsuranceID]  INT           IDENTITY (1, 1) NOT NULL,
    [PatientID]           INT           NULL,
    [InsuranceProviderID] INT           NULL,
    [PolicyNumber]        NVARCHAR (50) NULL,
    [CoverageStartDate]   DATE          NULL,
    [CoverageEndDate]     DATE          NULL,
    PRIMARY KEY CLUSTERED ([PatientInsuranceID] ASC),
    FOREIGN KEY ([InsuranceProviderID]) REFERENCES [dbo].[InsuranceProviders] ([InsuranceProviderID]),
    FOREIGN KEY ([PatientID]) REFERENCES [dbo].[Patients] ([PatientID])
);
GO

