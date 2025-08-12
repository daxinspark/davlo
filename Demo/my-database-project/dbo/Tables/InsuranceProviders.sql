CREATE TABLE [dbo].[InsuranceProviders] (
    [InsuranceProviderID] INT            IDENTITY (1, 1) NOT NULL,
    [Name]                NVARCHAR (100) NULL,
    [ContactNumber]       NVARCHAR (20)  NULL,
    [Address]             NVARCHAR (200) NULL,
    PRIMARY KEY CLUSTERED ([InsuranceProviderID] ASC)
);
GO

