CREATE TABLE [dbo].[PharmacyInventory] (
    [MedicationID]    INT NOT NULL,
    [QuantityInStock] INT NULL,
    [ReorderLevel]    INT NULL,
    PRIMARY KEY CLUSTERED ([MedicationID] ASC)
);
GO

