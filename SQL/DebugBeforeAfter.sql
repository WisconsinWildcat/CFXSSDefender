/****** Object:  Table [dbo].[DebugBeforeAfter]    Script Date: 9/4/2014 1:17:49 PM ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

SET ANSI_PADDING ON
GO

CREATE TABLE [dbo].[DebugBeforeAfter](
	[id] [int] IDENTITY(1,1) NOT NULL,
	[createDate] [datetime2](7) NOT NULL,
	[before] [nvarchar](max) NULL,
	[after] [nvarchar](max) NULL,
	[servername] [nvarchar](50) NULL,
	[scriptname] [nvarchar](50) NULL,
	[cgi] [nvarchar](max) NULL,
	[bakey] [varchar](50) NULL,
	[differences] [varchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

GO

SET ANSI_PADDING OFF
GO

ALTER TABLE [dbo].[DebugBeforeAfter] ADD  CONSTRAINT [DF_DebugBeforeAfter_createDate]  DEFAULT (getdate()) FOR [createDate]
GO
