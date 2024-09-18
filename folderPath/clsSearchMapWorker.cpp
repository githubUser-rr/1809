#include "clsSearchMapWorker.h"

#include "newstructs.h"


#include <QMutexLocker>
#include <QThread>
#include <fstream>
#include <QDir>
#include <QThread>
#include <QByteArray>




/*clsSearchMapWorker::clsSearchMapWorker(QString fName) : fileName(fName),defaultPath("C:\\Users\\user\\Desktop\\parseSession\\"),isLastPacket(false),isNewPacket(false)*/

QSet<QString> clsSearchMapWorker::pcapSet;
QHash<QString,QMutex*> clsSearchMapWorker::mutexMap;
QMutex clsSearchMapWorker::globalMt;

clsSearchMapWorker::clsSearchMapWorker(QString fName) : fileName(fName),defaultPath("C:\\Users\\remzi\\Desktop\\tParse\\"),isLastPacket(false),isNewPacket(false){

    this->startChrono = QDateTime::currentDateTime();



}

clsSearchMapWorker::~clsSearchMapWorker(){
    QMutexLocker locker(&this->m);
    QMutexLocker lck(&globalMt);

    /*for(auto hashIt = this->written.begin();hashIt != this->written.end() ; ++hashIt){
        QString key = hashIt.key();
        pcapSet.remove(key);
        QMutex* removeMutex = mutexMap.value(key,nullptr);
        mutexMap.remove(key);
        delete removeMutex;
    }*/
    //qDebug() << "Toplam Session Sayısı : " << pcapSet.size();
    this->written.clear();
    this->sessionMap.clear();
    this->h.clear();
    this->p.clear();
    qDebug() << "Mutex serbest bırakıldı ve elemanlar temizlendi.";


    /*for (auto it = sipMap.begin(); it != sipMap.end(); ++it) {
        QString key = it.key();  // Hash'in anahtarı
        sipSessionInfo value = it.value();  // Hash'in değeri

        // Anahtar bilgisi
        qDebug() << "Key: " << key;

        // sipSessionInfo içerisindeki her üyenin bilgilerini yazdırma
        qDebug() << "Messages: " << value.messages;
        qDebug() << "Source IP: " << value.sourceIp;
        qDebug() << "Destination IP: " << value.destIp;
        qDebug() << "Source Media Datas: " << value.sourceMediaDatas;
        qDebug() << "Source Ports: " << value.sourcePorts;
        qDebug() << "Destination Media Datas: " << value.destMediaDatas;
        qDebug() << "Destination Ports: " << value.destPorts;
        qDebug() << "Timestamp: " << value.tms.toString(Qt::ISODate); // QDateTime uygun formatta
        qDebug() << "Indices: " << value.indeks;
    }*/
    qDebug() << "Total Sip Cagrisi : " << this->sipMap.size();
    this->sipMap.clear();
    lck.unlock();
}

void clsSearchMapWorker::controlMap(){
    qDebug() << "Control Map " ;
    while (true) {
        QThread::msleep(250);
        QMutexLocker locker(&this->m);

        /*if (!this->isNewPacket) {
            qDebug() << "Yeni paket degil devam";
            continue;
        }*/
        auto sIt = sessionMap.begin();
        while (sIt != sessionMap.end()) {

            strSessıonInfo& sI = sIt.value();
            QString key = sIt.key();
            //std::cout << "Last process 1 " << std::endl;
            bool isneedsUpdate = (sI.packetCount >= 32 || this->isLastPacket);
            if (isneedsUpdate) {

                auto cIt = written.find(key);
                if (cIt != written.end()) {
                    if (cIt.value() != sI.packetCount) {
                        //std::cout << "Last process 3 " << std::endl;
                        //printSesionExtracter(sI);
                        appendNewPacketsFile(sI,cIt.value());
                        written[key] = sI.packetCount;
                        sIt = sessionMap.erase(sIt);
                    } else {
                        //std::cout << "Last process 4 " << std::endl;
                        sIt = sessionMap.erase(sIt);
                    }
                } else {
                    //std::cout << "Last process 5 " << std::endl;
                    //printSesionExtracter(sI);
                    appendNewPacketsFile(sI,0);
                    written[key] = sI.packetCount;
                    sIt = sessionMap.erase(sIt);
                }
            } else {
                //std::cout << "Last process 6 " << std::endl;
                sIt++;
            }

        }

        for(auto mIt = this->sipMap.begin() ; mIt != this->sipMap.end() ; ){
            const sipSessionInfo &sipValue = mIt.value();
            QString key = mIt.key();

            qint64 differenceTime = sipValue.tms.msecsTo(QDateTime::currentDateTime());
            QString lastMessage = sipValue.messages.last();
            QString lastSeq = sipValue.seqNumberList.last();


            bool controlSucces = (lastMessage.contains("200 OK") && lastSeq.contains("BYE"));
            bool timeOutControl = (differenceTime > 1200);


            if(controlSucces || timeOutControl){

                int totalPacketSize = sipValue.indeks.size();
                if(this->written.contains(key)){
                    if(totalPacketSize != this->written.value(key)){
                        //yazdır
                        if(controlSucces){
                            qDebug() << key << " call ıd basarili şekilde tamamlandı.";
                        }else{
                            qDebug() << key << " call ıd timeout !!";
                        }
                        int oldValue = this->written.value(key);
                        printSipPcap(sipValue,key,oldValue);
                        this->written[key] = totalPacketSize;
                        mIt = this->sipMap.erase(mIt);
                    }else{
                        mIt = this->sipMap.erase(mIt);
                    }
                }else{
                    //yazdır
                    if(controlSucces){
                        qDebug() << key << " call ıd basarili şekilde tamamlandı.";
                    }else{
                        qDebug() << key << " call ıd timeout !!";
                    }
                    printSipPcap(sipValue,key,0);
                    this->written[key] = totalPacketSize;
                    mIt = this->sipMap.erase(mIt);
                }
            }else{
                ++mIt;
            }
        }
        this->isNewPacket = false;
        locker.unlock();


        if (sessionMap.empty() && this->isLastPacket && this->sipMap.empty()) {
            //qDebug() << "Last process 8 " ;
            /*QDateTime eTime = QDateTime::currentDateTime();
            qint64 processTime = startChrono.secsTo(eTime);*/
            QDateTime eTime = QDateTime::currentDateTime();
            qint64 msecs = startChrono.msecsTo(eTime);

            qint64 seconds = msecs /  1000 ;
            qint64 mSeconds = msecs % 1000 ;
            double durationSeconds = seconds + mSeconds / 1000.0 ;

            qDebug()  << this->fileName << " pcap dosyasinin session parse islemi "
                      << durationSeconds << " saniyede tamamlandi."
                      << "Toplam session sayisi : " << written.size() ;
            break;
        }

    }

    emit finished();

}

void clsSearchMapWorker::setisLastPacket(bool isLast){
    qDebug()<< "setisLastPacket";
    QMutexLocker locker(&this->m);
    this->isLastPacket = isLast;
    locker.unlock();

}

void clsSearchMapWorker::setPacketsInfo(const u_char *pkt_data, const pcap_pkthdr *hdr){
    QMutexLocker locker(&this->m);
    QVector<quint8> pData (pkt_data,pkt_data+hdr->len);

    this->p.push_back(pData);
    this->h.push_back(*hdr);

    // p == QVector<QVector<quint8>>
    this->isNewPacket = true;
    locker.unlock();

}

void clsSearchMapWorker::updateSessionMap(const QString &key, const strSessıonInfo &newMap){
    QMutexLocker locker(&this->m);

    this->sessionMap[key] = newMap;
    this->isNewPacket = true;
    locker.unlock();

}

void clsSearchMapWorker::appendSipSessionInfo(sipPacket s){
    QMutexLocker locker(&this->m);
    this->isNewPacket= true;
    //this->sipPackets.append(sPacket);

    if(this->sipMap.contains(s.callId)){
        sipSessionInfo &sip = this->sipMap[s.callId];
        switch(s.control){
        case 1:
            if(sip.sourceIp.isEmpty()){
                sip.sourceIp = s.ipAdd;
            }
            sip.sourceMediaDatas.append(s.mediaDatas);
            sip.sourcePorts.append(s.ports);
            break;

        case 0:
            if(sip.destIp.isEmpty()){
                sip.destIp = s.ipAdd;
            }
            sip.destMediaDatas.append(s.mediaDatas);
            sip.destPorts.append(s.ports);
            break;

        case -1:
            break;

        default:
            qDebug() << "Fail Switch Case";
            break;
        }
        sip.messages.append(s.messages);
        sip.tms = s.tms;
        sip.indeks.append(s.pIndex);
        sip.seqNumberList.append(s.seqNumber);

    }else{
        sipSessionInfo nSipInfo;
        nSipInfo.messages.append(s.messages);
        nSipInfo.seqNumberList.append(s.seqNumber);
        nSipInfo.tms = s.tms;
        nSipInfo.indeks.push_back(s.pIndex);

        switch(s.control){
        case -1:
            nSipInfo.sourceIp = "";
            nSipInfo.destIp = "";
            nSipInfo.sourceMediaDatas = QStringList();
            nSipInfo.sourcePorts = QStringList();
            nSipInfo.destMediaDatas = QStringList();
            nSipInfo.destPorts = QStringList();
            break;

        case 0:
            nSipInfo.sourceIp = "";
            nSipInfo.destIp = s.ipAdd;
            nSipInfo.sourceMediaDatas = QStringList();
            nSipInfo.sourcePorts = QStringList();
            nSipInfo.destMediaDatas.append(s.mediaDatas);
            nSipInfo.destPorts.append(s.ports);
            break;

        case 1:
            nSipInfo.sourceIp = s.ipAdd;
            nSipInfo.destIp = "";
            nSipInfo.sourceMediaDatas.append(s.mediaDatas);
            nSipInfo.sourcePorts.append(s.ports);
            nSipInfo.destMediaDatas = QStringList();
            nSipInfo.destPorts = QStringList();
            break;

        default:
            qDebug() << "Switch - case hatası";
                break;
        }
        this->sipMap[s.callId] = nSipInfo;
    }

    qDebug() << "Sip Map size : " << this->sipMap.size();


    locker.unlock();


}

void clsSearchMapWorker::createSipMap(){
    QMutexLocker lck(&this->m);

    for(const sipPacket& s : this->sipPackets){
        if(this->sipMap.contains(s.callId)){
            sipSessionInfo &sip = this->sipMap[s.callId];
            switch(s.control){
            case 1:
                if(sip.sourceIp.isEmpty()){
                    sip.sourceIp = s.ipAdd;
                }
                sip.sourceMediaDatas.append(s.mediaDatas);
                sip.sourcePorts.append(s.ports);
                break;

            case 0:
                if(sip.destIp.isEmpty()){
                    sip.destIp = s.ipAdd;
                }
                sip.destMediaDatas.append(s.mediaDatas);
                sip.destPorts.append(s.ports);
                break;

            case -1:
                break;

            default:
                qDebug() << "Fail Switch Case";
                break;
            }
            sip.messages.append(s.messages);
            sip.tms = s.tms;
            sip.indeks.append(s.pIndex);

        }else{
            sipSessionInfo nSipInfo;
            nSipInfo.messages.append(s.messages);
            switch(s.control){
            case -1:
                nSipInfo.sourceIp = "";
                nSipInfo.destIp = "";
                nSipInfo.sourceMediaDatas = QStringList();
                nSipInfo.sourcePorts = QStringList();
                nSipInfo.destMediaDatas = QStringList();
                nSipInfo.destPorts = QStringList();
                nSipInfo.tms = s.tms;
                nSipInfo.indeks.push_back(s.pIndex);
                break;

            case 0:
                nSipInfo.sourceIp = "";
                nSipInfo.destIp = s.ipAdd;
                nSipInfo.sourceMediaDatas = QStringList();
                nSipInfo.sourcePorts = QStringList();
                nSipInfo.destMediaDatas.append(s.mediaDatas);
                nSipInfo.destPorts.append(s.ports);
                nSipInfo.tms = s.tms;
                nSipInfo.indeks.push_back(s.pIndex);
                break;

            case 1:
                nSipInfo.sourceIp = s.ipAdd;
                nSipInfo.destIp = "";
                nSipInfo.sourceMediaDatas.append(s.mediaDatas);
                nSipInfo.sourcePorts.append(s.ports);
                nSipInfo.destMediaDatas = QStringList();
                nSipInfo.destPorts = QStringList();
                nSipInfo.tms = s.tms;
                nSipInfo.indeks.push_back(s.pIndex);
                break;

            default:
                qDebug() << "Switch - case hatası";
                break;
            }
            this->sipMap[s.callId] = nSipInfo;
        }
    }
    this->sipPackets.clear();
    qDebug() << "Sip Map size : " << this->sipMap.size();
    lck.unlock();
}

void clsSearchMapWorker::printSessionInfo(QString ses, strSessıonInfo sI){
    //bu kullanılmıyor ihtiyaç olursa doldur
}

void clsSearchMapWorker::printSesionExtracter(strSessıonInfo sInfo){
    QString sourceToDestControl = sInfo.sourceIP + "_" + QString::number(sInfo.sourcePort) + "_" + sInfo.destIP + "_" + QString::number(sInfo.destPort) + "_" + sInfo.protocol;
    QString destToSourceControl = sInfo.destIP + "_" + QString::number(sInfo.destPort) + sInfo.sourceIP + "_" + QString::number(sInfo.sourcePort) + "_" + sInfo.protocol;
    QString pcapName = this->defaultPath + sourceToDestControl + ".pcap";


    QVector<QVector<quint8>> prePackets;
    QVector<pcap_pkthdr> preHeaders;

    bool isFound = false;
    int flag = -1;
    qDebug() << " -- ";
    if(pcapSet.contains(sourceToDestControl) || pcapSet.contains(destToSourceControl)){
        isFound = true;
        flag = pcapSet.contains(sourceToDestControl) ? 1 : 0;
        if(flag == 0){//bu durumda güncelle
            pcapName = this->defaultPath + destToSourceControl + ".pcap";
            qDebug() << pcapName;
        }
    }

    //QString pcapName = this->defaultPath + "session_" + sInfo.protocol + "_" + QString::number(sInfo.streamIndex) + ".pcap";

    pcap_t* handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (handle == nullptr) {
        qDebug() << "Pcap dosya oluşturma hatası: " << pcap_geterr(handle) ;
    }

    pcap_dumper_t* d = pcap_dump_open(handle, pcapName.toUtf8().constData());
    if (d == nullptr) {
        qDebug() << "Pcap dosya açma hatası: " << pcap_geterr(handle) ;
        pcap_close(handle);
    }
    //append modu için
    //pcap_dumper_t* dmp = pcap_dump_open_append(handle,pcapName.toUtf8().constData()); // dosya yoksa hata döndürür bu duruma bir mutex ekle

    if(isFound){
        qDebug() << "Session Bulundu okuyup üstüne yazılıyor.";
        //int flag = pcapSet.contains(sourceToDestControl) ? 1 : 0;
        char preerrbuf[PCAP_ERRBUF_SIZE];
        pcap_t* prehandle = nullptr;


        const char* filename = pcapName.toUtf8().constData();
        prehandle = pcap_open_offline(filename,preerrbuf);
        if(prehandle == nullptr){
            qWarning() << "Önceki pcap dosysı açma hatası !!" ;
            //pcap_dump_close(prehandle);
        }else{
            struct pcap_pkthdr* preHeader;
            const u_char* preData;
            int preResult;

            while((preResult = pcap_next_ex(prehandle,&preHeader,&preData)) >= 0){
                if(preResult == 0) {
                    continue;
                }
                if (preResult == -1 || preResult == PCAP_ERROR ) {
                    qDebug() << "PCAP okuma hatası: " << pcap_geterr(prehandle);
                    break;
                }


                //buna gerek yok
                QVector<quint8> packet_data(preData, preData + preHeader->caplen);
                prePackets.push_back(packet_data);
                preHeaders.push_back(*preHeader);
                //pcap_dump(reinterpret_cast<u_char*>(d),preHeader,preData);
                //qDebug() << "Yazıldı";
            }

            //pcap_dump(reinterpret_cast<u_char*>(d),&preHeaders,prePackets.data());
            pcap_close(prehandle);
        }


    }
    //burası olanları silip bunları yazıyor . append tarzı yazmak gerekiyor
    for(int i=0 ;i<=prePackets.size();i++){
        const pcap_pkthdr& newH = preHeaders[i];
        const QVector<quint8>& newP = prePackets[i];
        pcap_dump(reinterpret_cast<u_char*>(d), &newH,newP.data());
    }


    for (const auto& i : sInfo.packetIndex) {
        const pcap_pkthdr& header = this->h[i-1];
        const QVector<quint8>& packet = this->p[i-1];
        pcap_dump(reinterpret_cast<u_char*>(d), &header, packet.data());
    }
    pcapSet.insert(sourceToDestControl);
    pcap_dump_close(d);
    pcap_close(handle);

}

void clsSearchMapWorker::appendNewPacketsFile(strSessıonInfo s,int lastIndeks){
    //staticc bir mutex kulan bu fonksiyon aktfik olduğunda kitle
    //yazma işlemi tamma sınıf kontrol için mutex kodla
    QString sourceToDestControl = s.protocol + "_" + s.sourceIP + "_" + QString::number(s.sourcePort) + "_" + s.destIP + "_" + QString::number(s.destPort) ;
    QString destToSourceControl = s.protocol + "_" + s.destIP + "_" + QString::number(s.destPort) + "_" + s.sourceIP + "_" + QString::number(s.sourcePort) ;
    QString pcapName = this->defaultPath + sourceToDestControl + ".pcap";


    pcap_t* handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (handle == nullptr) {
        qDebug() << "Append New Packets ; Pcap dosya oluşturma hatası: " << pcap_geterr(handle) ;
    }

    pcap_dumper_t* d;
    QMutex* mt = nullptr;

    QMutexLocker globalLocker(&globalMt);
    if(pcapSet.contains(sourceToDestControl) || pcapSet.contains(destToSourceControl)){
        //qDebug() << "Var " ;
        if(pcapSet.contains(destToSourceControl)){
            pcapName = this->defaultPath + destToSourceControl + ".pcap";
            qDebug() << pcapName;
        }
        d = pcap_dump_open_append(handle,pcapName.toUtf8().constData());
        if (d == nullptr) {
            qDebug() << "Pcap Dumper Append açma hatası: " << pcap_geterr(handle);
            pcap_close(handle);
        }
        //mutexMap[pcapName].lock();
        //mt = mutexMap[pcapName];
        //mt.lock();
        //mt = &mutexMap[pcapName];
        mt = mutexMap.value(pcapName,nullptr);
        mt->lock();
    }else{
        //qDebug() << "Yok " ;
        d = pcap_dump_open(handle,pcapName.toUtf8().constData());
        if(d == nullptr){
            qDebug() << "Pcap Dumper açma hatası: " << pcap_geterr(handle);
            pcap_close(handle);
        }
        //pcapSet.insert(sourceToDestControl);
        //mutexMap.insert(pcapName,QMutex());
        //mt = mutexMap[pcapName];
        //mt = &mutexMap[pcapName];
        //mt.lock();

        pcapSet.insert(sourceToDestControl);
        mt = new QMutex();
        mutexMap.insert(pcapName,mt);
        mt->lock();
    }
    globalLocker.unlock();
    //burda br sorun var
    //qDebug() << "Last Indeks : " << lastIndeks << "Vector Size : " << s.packetIndex.size();
    for(int i=lastIndeks;i<s.packetIndex.size();++i){
        int pIndex = s.packetIndex[i];
        //qDebug() << "Eleman" << i << ":" << pIndex;
        const pcap_pkthdr& header = this->h[pIndex-1];
        const QVector<quint8>& packet = this->p[pIndex-1];
        pcap_dump(reinterpret_cast<u_char*>(d),&header,packet.data());
    }


    mt->unlock();

    pcap_dump_close(d);
    pcap_close(handle);




}

void clsSearchMapWorker::printSipPcap(const sipSessionInfo &info, const QString &sipCall,int lastIndex){

    QString pcapName = this->defaultPath + "sip_CallId_" + sipCall + ".pcap";
    pcap_t* handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (handle == nullptr) {
        qDebug() << "Append New Sip Packets ; Pcap dosya oluşturma hatası: " << pcap_geterr(handle) ;
    }

    pcap_dumper_t* d;
    QMutex* mt = nullptr;

    QMutexLocker globalLocker(&globalMt);
    if(pcapSet.contains(sipCall)){
        //qDebug() << "Var " ;

        d = pcap_dump_open_append(handle,pcapName.toUtf8().constData());
        if (d == nullptr) {
            qDebug() << "Sip Pcap Dumper Append açma hatası: " << pcap_geterr(handle);
            pcap_close(handle);
        }
        mt = mutexMap.value(pcapName,nullptr);
        mt->lock();
    }else{
        d = pcap_dump_open(handle,pcapName.toUtf8().constData());
        if(d == nullptr){
            qDebug() << "Sip Pcap Open Dumper açma hatası: " << pcap_geterr(handle);
            pcap_close(handle);
        }

        pcapSet.insert(sipCall);
        mt = new QMutex();
        mutexMap.insert(pcapName,mt);
        mt->lock();
    }
    globalLocker.unlock();


    //qDebug() << "Last Indeks : " << lastIndex << "Vector Size : " << info.indeks.size();
    for(int i=lastIndex;i<info.indeks.size();++i){
        int pIndex = info.indeks[i];
        //qDebug() << "Eleman" << i << ":" << pIndex;
        const pcap_pkthdr& header = this->h[pIndex-1];
        const QVector<quint8>& packet = this->p[pIndex-1];
        pcap_dump(reinterpret_cast<u_char*>(d),&header,packet.data());
    }


    mt->unlock();

    pcap_dump_close(d);
    pcap_close(handle);


}