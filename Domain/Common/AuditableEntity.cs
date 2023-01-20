using System;

namespace ApiGrup.Domain.Common
{
    public abstract class AuditableEntity
    {
        public DateTime CreatedOn { get; set; }

        public string CreatedBy { get; set; }

        public DateTime? LastModifiedOn { get; set; }

        public string LastModifiedBy { get; set; }
    }
}
