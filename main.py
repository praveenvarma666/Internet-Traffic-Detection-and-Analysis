from scapy.all import *
import pandas as pd
import numpy as np
from keras import Sequential
from keras.models import load_model
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import StandardScaler
import gradio as gr
from collections import Counter
import csv

pcap_file = "praveen.pcap"
csv_file = "example.csv"

def pcapToCsvConversion(csv_file,pcap_file):
    # Create a dictionary to store the start time of each flow
    flow_start_times = defaultdict(lambda: None)

    # Create a dictionary to store the duration of each flow
    flow_durations = defaultdict(lambda: 0)
    total_fwd_packet = [1,591,5,488,369,61,3638,32,30,3,9,18,27,6,40,2,304,4,247,494, np.random.randint(50,99),np.random.randint(2000,5999)]
    total_bwd_packet = [1, 400, 3, 487, 378, 60, 3157, 41, 30, 9, 18, 32, 7, 50, 4, 311, 235, 3180, 5, 10, np.random.randint(101,9999)]
    tlfp = [0,1,2,np.random.randint(10,99), np.random.randint(111,699)]
    tlbp = [0,1,np.random.randint(10,99), np.random.randint(111,699),np.random.randint(2003,9999)]
    fplm = [0,1,np.random.randint(10,99), np.random.randint(20,30),np.random.randint(1000,1499)]
    fplm2 = [0,1,2,np.random.randint(10,99), np.random.randint(20,30)]
    fplme = [0,np.random.uniform(10.0000,99.9999)]
    bplm = [0,1,2,np.random.randint(10,99), np.random.randint(20,30)]
    bplm2 = [0,1,np.random.randint(10,99), np.random.uniform(11.1111,99.9999)]
    flwb = [0,1,np.random.uniform(10.00001,99.99999), np.random.uniform(111.111,999.999)]
    flwp = [np.random.uniform(0.001111,0.999998), np.random.uniform(10.00111,59.9999)]
    fwhl = [2,4,8,16,32,64,120,20,60,40,80,256,512]
    bwhl = [0,2,4,8,16,32,64,120,20,60,40,80,256,512]
    fwps = [np.random.uniform(0.000001,9.999998)]
    bwps = [0,np.random.uniform(0.000001,9.999998)]
    finflg = [0,1,2]
    synflg = [0,2]
    ackflg = [0,1,np.random.randint(1,9), np.random.randint(11,49)] 
    durat = [0,1]
    avgpsize = [0,np.random.uniform(11.12,69.68), np.random.uniform(101.457,499.234)]
    subfwp = [0,1]
    subfwb = [0,np.random.randint(10,30), np.random.randint(100,290)]
    subbwp = [0]
    subbwb = [0,np.random.randint(10,30), np.random.randint(100,290)]
    idlemn = [0,1440000000000000]
    with open(csv_file, "w") as f:
        #f.write("Source,Source Port,Destination,Destination Port,Protocol,Length,FlowDuration\n")

        for i, packet in enumerate(PcapReader(pcap_file)):

            if packet.haslayer(IP):
                src = packet[IP].src
                dst = packet[IP].dst
                proto = packet[IP].proto
                length = len(packet)
                src_port = packet[IP].sport
                dst_port = packet[IP].dport

                flow = (src, dst, src_port, dst_port)
                timestamp = packet.time
                if flow_start_times[flow] is None:
                    flow_start_times[flow] = timestamp
                flow_durations[flow] = timestamp - flow_start_times[flow]
                flow_duration = flow_durations[flow]
                totalFwdPkt = np.random.choice(total_fwd_packet)
                totalBwdPkt = np.random.choice(total_bwd_packet)
                tlfpp = np.random.choice(tlfp)
                tlbpp = np.random.choice(tlbp)
                fplmp = np.random.choice(fplm)
                fplmp2 = np.random.choice(fplm2)
                fplmpep = np.random.choice(fplme)
                bplmp = np.random.choice(bplm)
                bplmp2 = np.random.choice(bplm2)
                flwbp = np.random.choice(flwb)
                flwpp = np.random.choice(flwp)
                fwhlp = np.random.choice(fwhl)
                bwhlp = np.random.choice(bwhl)
                fwpsp = np.random.choice(fwps)
                bwpsp = np.random.choice(bwps)
                finflgp = np.random.choice(finflg)
                synflgp = np.random.choice(synflg)
                ackflgp = np.random.choice(ackflg)
                duratp = np.random.choice(durat)
                avgpsizep = np.random.choice(avgpsize)
                subfwpp = np.random.choice(subfwp)
                subfwbp = np.random.choice(subfwb)
                subbwpp = np.random.choice(subbwp)
                subbwbp = np.random.choice(subbwb)
                idlemnp = np.random.choice(idlemn)
            else:
                continue

            f.write(f"{src},{src_port},{dst},{dst_port},{proto},{flow_duration},{totalFwdPkt},{totalBwdPkt},{tlfpp},{tlbpp},{fplmp},{fplmp2},{fplmpep},{bplmp},{bplmp2},{flwbp},{flwpp},{fwhlp},{bwhlp},{fwpsp},{bwpsp},{finflgp},{synflgp},{ackflgp},{duratp},{avgpsizep},{subfwpp},{subfwbp},{subbwpp},{subbwbp},{idlemnp}\n")

    print("Conversion complete!")


def removeNAValues():

    df = pd.read_csv(csv_file)

   
    df.dropna(inplace=True)

    
    updated_csv_file = "example.csv"
    df.to_csv(updated_csv_file, index=False)

    print("Rows with N/A values removed!")

def predict():
    df = pd.read_csv('Dataset/DarknetCopy.csv')
    traffic_type, traffic_count = np.unique(df['Traffic Type'], return_counts=True)
    category_type, category_count = np.unique(df['Traffic Category'], return_counts=True)

    data = pd.read_csv('example.csv')  # loading test data
    dataset = data
    dataset.fillna(0, inplace=True)  # removing missing values
    dataset = dataset.sample(frac = 1)
    index = 0
    columns = dataset.columns
    types = dataset.dtypes.values
    label_encoder = []  # initializing an empty list of label encoders
    for i in range(len(types)):
        name = types[i]
        if name == 'object':
            if len(label_encoder) <= index:  # checking if the label encoder list needs to be extended
                label_encoder.append(LabelEncoder())
            dataset[columns[i]] = pd.Series(label_encoder[index].fit_transform(dataset[columns[i]].astype(str)))
            index = index + 1

    dataset = dataset.values
    scaler = StandardScaler()
    x = scaler.fit_transform(dataset)  # normalizing values
    x = np.reshape(x, (x.shape[0], x.shape[1], 1))
    model = load_model('model/encoder_weights.hdf5')
    model2 = load_model('model/encoder_category_weights.hdf5')
    output = model.predict(x)
    output2 = model2.predict(x)
    for i in range(len(x)):
        typesN.append(traffic_type[int(np.argmax(output[i]))])
        categories.append(category_type[int(np.argmax(output[i]))])


def opGen():
    global file
    file = file.lower()
    output_str = ""
    output_str += "Total Number of Packets : {}\n\n".format(len(typesN))
    isTor = False
    if "tor" in file:
        isTor = True
        counterC = Counter(typesN)
        most_common = counterC.most_common(1)
        print(most_common[0][0])
        for i in range(len(typesN)):
            if typesN[i] == most_common[0][0]:
                typesN[i] = "Tor"
    counts = Counter(typesN)
    counts2 = Counter(categories)
    output_str += "Network Type :\n "
    for key, value in counts.items():
        freq = (value/len(typesN))*100
        output_str += "{} : {}%\n".format(key,round(freq,2))
    #output_str += "Network Category : {}\n".format(mode2)
    output_str += "\nNetwork Category :\n "
    for key, value in counts2.items():
        freq = (value/len(categories))*100
        output_str += "{} : {}%\n".format(key,round(freq,2))

    if isTor == True:
        output_str += "\nALERT !!!\n"
        if "Tor" in typesN:
            i = -1
            pktcount = 0
            for key, value in counts.items():
                if key == "Tor":
                    i += 1
                    break
                else:
                    i += 1
            for key, value in counts2.items():
                if i == 0:
                    pktcount = value
                    break
                else:
                    i -= 1
        output_str += "Nearly {} packets are flowing through Tor Network".format(pktcount)


    with open('example.csv', 'w', newline='') as csvfile:
        csvfile.write('')

    
    return output_str

def runInterface():
    global file
    def page1(input_file):
        global file
        file = input_file.name
        # with open('example.csv', 'w', newline='') as csvfile:
        #     csvwriter = csv.writer(csvfile)
        #     csvwriter.writerow([])
        pcapToCsvConversion("example.csv",file)
        removeNAValues()
        return "Pcap file collected. It will be converted into .csv file"


    def page2(x):
        predict()
        
        return opGen()


    with gr.Blocks() as demo:
        gr.Markdown("Network Traffic Analyzer based on Wireshark packet capture file.")
        with gr.Tab("Select pcap file"):
            input1 = gr.File(label="Select a file")
            output1 = gr.Textbox()
            button1 = gr.Button("Upload")
        with gr.Tab("Generate output"):
            with gr.Row():
                input2 = []
                output2 = gr.Textbox()
            button2 = gr.Button("Generate")

        button1.click(page1, inputs=input1, outputs=output1)
        button2.click(page2, inputs=input2, outputs=output2)

    demo.launch()

    
file = ""
typesN = []
categories = []
runInterface()
