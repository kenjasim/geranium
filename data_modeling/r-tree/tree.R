require("C50")
data <- read.table("kddcup.data", header=FALSE, sep="," )
data
data <- data[ sample( nrow( data ) ), ]
X <- data[,1:41]
n <- c("duration", 
       "protocol_type", 
       "service", 
       "flag", 
       "src_bytes", 
       "dst_bytes", 
       "land", 
       "wrong_fragment", 
       "urgent", 
       "hot", 
       "num_failed_logins", 
       "logged_in", 
       "num_compromised", 
       "root_shell", 
       "su_attempted", 
       "num_root", 
       "num_file_creations", 
       "num_shells", 
       "num_access_files", 
       "num_outbound_cmds", 
       "is_host_login", 
       "is_guest_login", 
       "count", 
       "srv_count", 
       "serror_rate", 
       "srv_serror_rate",
       "rerror_rate",
       "srv_rerror_rate", 
       "same_srv_rate", 
       "diff_srv_rate", 
       "srv_diff_host_rate", 
       "dst_host_count", 
       "dst_host_srv_count", 
       "dst_host_same_srv_rate", 
       "dst_host_diff_srv_rate", 
       "dst_host_same_src_port_rate",
       "dst_host_srv_diff_host_rate", 
       "dst_host_serror_rate", 
       "dst_host_srv_serror_rate", 
       "dst_host_rerror_rate", 
       "dst_host_srv_rerror_rate")
colnames(X) <- n
y <- data[,42]
model <- C50::C5.0( X, y, trials=10 )
summary( model )
plot(model)
test <- read.table("test", header=FALSE, sep="," )
test <- test[ sample( nrow( test ) ), ]
testX <- test[,1:41]
testy <- test[,42]
p <- predict(model, testX, type="class" )
p
testy
sse = sum((p - testy$MEDV)^2)
sum( p == testy ) / length( p )
string <- id=\"See5/C5.0 2.07 GPL Edition 2013-03-13\"\nentries=\"1\"\nrules=\"6\" default=\"0\"\nconds=\"2\" cover=\"322\" ok=\"321\" lift=\"1.55321\" class=\"0\"\ntype=\"2\" att=\"UniformityOfCellSize\" cut=\"3\" result=\"<\"\ntype=\"2\" att=\"BareNuclei\" cut=\"2\" result=\"<\"\nconds=\"2\" cover=\"305\" ok=\"304\" lift=\"1.55268\" class=\"0\"\ntype=\"2\" att=\"UniformityOfCellShape\" cut=\"2\" result=\"<\"\ntype=\"2\" att=\"BareNuclei\" cut=\"3\" result=\"<\"\nconds=\"2\" cover=\"310\" ok=\"307\" lift=\"1.54282\" class=\"0\"\ntype=\"2\" att=\"UniformityOfCellShape\" cut=\"2\" result=\"<\"\ntype=\"2\" att=\"NormalNucleoli\" cut=\"2\" result=\"<\"\nconds=\"2\" cover=\"137\" ok=\"132\" lift=\"2.65679\" class=\"1\"\ntype=\"2\" att=\"BareNuclei\" cut=\"3\" result=\">\"\ntype=\"2\" att=\"NormalNucleoli\" cut=\"2\" result=\">\"\nconds=\"2\" cover=\"179\" ok=\"170\" lift=\"2.62324\" class=\"1\"\ntype=\"2\" att=\"UniformityOfCellShape\" cut=\"2\" result=\">\"\ntype=\"2\" att=\"BareNuclei\" cut=\"2\" result=\">\"\nconds=\"2\" cover=\"175\" ok=\"166\" lift=\"2.61978\" class=\"1\"\ntype=\"2\" att=\"UniformityOfCellSize\" cut=\"3\" result=\">\"\ntype=\"2\" att=\"UniformityOfCellShape\" cut=\"2\" result=\">\"\n"
write(string, file="string.txt")
write(capture.output(summary(model)), "c50model.txt")
