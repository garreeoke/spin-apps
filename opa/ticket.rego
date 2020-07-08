package opa.pipelines

deny["Every pipeline must have ticket parameter"] {
   ticket = [d |d = input.pipeline.parameterConfig[_].name; d == "ticket"]
   count(input.pipeline.stages[_]) > 0
   count(ticket) == 0
}
