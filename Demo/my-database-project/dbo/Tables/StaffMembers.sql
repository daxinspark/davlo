CREATE TABLE [dbo].[StaffMembers] (
    [StaffID]   INT            IDENTITY (1, 1) NOT NULL,
    [FirstName] NVARCHAR (50)  NULL,
    [LastName]  NVARCHAR (50)  NULL,
    [RoleID]    INT            NULL,
    [Phone]     NVARCHAR (20)  NULL,
    [Email]     NVARCHAR (100) NULL,
    [HireDate]  DATE           NULL,
    PRIMARY KEY CLUSTERED ([StaffID] ASC),
    FOREIGN KEY ([RoleID]) REFERENCES [dbo].[StaffRoles] ([StaffRoleID])
);
GO

